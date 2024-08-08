from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models
import uuid
from django.core.cache import cache
from django.utils.translation import gettext_lazy as _


class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    email = models.EmailField(_("email address"), unique=True)
    mobile_no = models.CharField(max_length=15, unique=False, null=True, blank=True)  # TODO: why char here ?
    preferred_language = models.CharField(max_length=100, default=None, null=True, blank=True)
    task_interests = models.CharField(max_length=100, default=None, null=True, blank=True)
    profile_bio = models.CharField(max_length=100, default=None, null=True, blank=True)
    is_subscription_active = models.BooleanField(
        default=False,
        help_text="This field determines whether the user's subscription is active or inactive. Be cautious when changing this setting."
    )
    modified_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    date_of_birth = models.DateField(_("date of birth"), null=True, blank=True)
    groups = models.ManyToManyField(Group, related_name='chanakya_user_set', blank=True)
    user_permissions = models.ManyToManyField(Permission, related_name='chanakya_user_set', blank=True)
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ['mobile_no', 'username']

    def get_full_name(self):
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        if self.first_name:
            return self.first_name
        return ""

    def save(self, *args, **kwargs):
        # Delete cache for the user based on email
        cache_key = self.email
        cache.delete(cache_key)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.email
