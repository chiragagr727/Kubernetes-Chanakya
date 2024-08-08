from django.db import models
from chanakya.enums.role_enum import RoleEnum
from uuid import uuid4
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from django.core.cache import cache
import django.utils.timezone

user = get_user_model()


class ConversationModel(models.Model):
    id = models.UUIDField(default=uuid4, unique=True, primary_key=True)
    title = models.CharField(max_length=100, default="New Chat")
    created = models.DateTimeField(default=django.utils.timezone.now, verbose_name='created')
    user = models.ForeignKey(user, related_name='user', on_delete=models.CASCADE, null=True)
    updated = models.DateTimeField(_("updated"), auto_now=True)

    def save(self, *args, **kwargs):
        # Delete cache for the user based on email
        cache_key = f"conversation_{self.id}"
        cache.delete(cache_key)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.title


class MessageModel(models.Model):
    id = models.UUIDField(default=uuid4, unique=True, primary_key=True)
    content = models.TextField()
    role = models.CharField(max_length=10, choices=RoleEnum.choices())
    conversation = models.ForeignKey(ConversationModel, related_name='messages', on_delete=models.CASCADE)
    created = models.DateTimeField(default=django.utils.timezone.now, verbose_name='created')
    updated = models.DateTimeField(_("updated"), auto_now=True)

    def __str__(self):
        return self.content


class FeedbackModel(models.Model):
    id = models.AutoField(primary_key=True)
    message = models.ForeignKey(MessageModel, related_name='message', on_delete=models.CASCADE)
    is_unliked = models.BooleanField(default=False)
    feedback = models.TextField(default=None, null=True)
    category = models.CharField(max_length=30, null=True, blank=True, default=None)
    created = models.DateTimeField(default=django.utils.timezone.now)

    def __str__(self):
        return self.feedback
