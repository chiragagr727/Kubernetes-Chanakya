import logging
from django.core.cache import cache
from chanakya.middleware import generate_response
from chanakya.models.subscription_model import UserSubscription
from rest_framework import status
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class PremiumFeaturesMiddleware:
    PREMIUM_USER_VALIDATION = ['/chanakya-premium/google-search/']
    CACHE_TIMEOUT = 300

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path
        if path in self.PREMIUM_USER_VALIDATION:
            user_info = request.META.get('user', None)
            logger.info(f"************** chanakya premium validation***********************")
            logger.debug(f"chanakya premium user:\n{user_info.email}")
            logger.debug(f"chanakya premium validation:\n{user_info.is_subscription_active}")
            if not user_info:
                return generate_response('Unauthorized', 'User is missing. Contact Admin', status.HTTP_403_FORBIDDEN)

            cache_key = f"subscription_status_{user_info.id}"
            subscription_active = cache.get(cache_key)

            if subscription_active is None:
                subscription_active = UserSubscription.objects.filter(
                    user=user_info, active=True, expiry_date__gt=datetime.now()
                ).exists()
                cache.set(cache_key, subscription_active, self.CACHE_TIMEOUT)

            if not subscription_active:
                return generate_response(
                    'Unauthorized',
                    'Your subscription is not active. Please renew your subscription to continue accessing the service',
                    status.HTTP_402_PAYMENT_REQUIRED
                )

        return self.get_response(request)
