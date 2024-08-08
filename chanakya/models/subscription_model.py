from django.db import models
from chanakya.enums.subscription_enum import SubsEnum
from datetime import datetime
from uuid import uuid4
from django.contrib.auth import get_user_model
import django.utils.timezone

user = get_user_model()


class UserSubscription(models.Model):
    id = models.UUIDField(default=uuid4, unique=True, primary_key=True)
    provider_type = models.CharField(max_length=10, choices=SubsEnum.choices())
    user = models.ForeignKey(user, on_delete=models.CASCADE, related_name='subscriptions')
    active = models.BooleanField(default=True)
    start_date = models.DateTimeField(auto_now_add=True)
    expiry_date = models.DateTimeField(blank=True, null=True)
    request_id = models.CharField(max_length=50, default=None, blank=True, null=True)
    type = models.CharField(max_length=200, default=None, blank=True, null=True)
    transaction_id = models.CharField(max_length=100, default=None, blank=True, null=True)
    period_type = models.CharField(max_length=50, default=None, blank=True, null=True)
    subscription_paused = models.BooleanField(default=False)
    subscription_cancel = models.BooleanField(default=False)
    subscription_expire = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=django.utils.timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    def is_active(self):
        return self.active and (self.expiry_date is None or self.expiry_date > datetime.now())

    def subscription_duration(self):
        if self.expiry_date:
            return (self.expiry_date - self.start_date).days
        return None

    def cancel(self):
        self.active = False
        self.save()

    def __str__(self):
        return f"{self.user.username}"
