from django.contrib.auth import get_user_model
from rest_framework import serializers

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'mobile_no', 'preferred_language',
                  'task_interests', 'profile_bio', 'is_active', 'is_subscription_active', 'date_of_birth']
        extra_kwargs = {'password': {'write_only': True}}


class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['mobile_no', 'preferred_language', 'task_interests', 'profile_bio', 'date_of_birth']
