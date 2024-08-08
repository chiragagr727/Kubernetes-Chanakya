from rest_framework import viewsets, status
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.core.cache import cache
from premium_features.serializer.premium_user_serializer import UserSerializer
from chanakya.utils import custom_exception
import logging

User = get_user_model()
logger = logging.getLogger(__name__)


class PremiumUserViewSet(viewsets.ViewSet):

    def list(self, request):
        user = request.META.get("user", None)
        if not user:
            raise custom_exception.DataNotFound("No User Found")

        cache_key = f"user_subscription_data_{user.id}"
        user_data = cache.get(cache_key)

        if not user_data:
            user_data = UserSerializer(user).data
            cache.set(cache_key, user_data, timeout=60 * 15)  # Cache timeout set to 15 minutes

        return Response(user_data, status=status.HTTP_200_OK)
