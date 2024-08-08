from django.db import models
from django.core.cache import cache
from django.db.models.signals import post_save
from django.dispatch import receiver
import uuid
from django.utils.translation import gettext_lazy as _
import django.utils.timezone


class PromptsModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=100, blank=True)
    start_token = models.CharField(max_length=100, blank=True)
    end_token = models.CharField(max_length=100, blank=True)
    user_token = models.CharField(max_length=100, blank=True)
    assistant_token = models.CharField(max_length=100, blank=True)
    eot_token = models.CharField(max_length=100, blank=True)
    system_message = models.CharField(max_length=8000, blank=True)
    begin_of_text_token = models.CharField(max_length=100, blank=True)
    system_token = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(default=django.utils.timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    # Optional: If you want to automatically clear cache on model save
    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        self.update_cache()

    def update_cache(self):
        cache_key = self.get_cache_key(self.name)  # Pass self.id to the method
        cache.set(cache_key, self, timeout=60 * 60 * 720)

    @classmethod
    def get_cache_key(cls, name):
        return name
