from celery import shared_task
from django.contrib.auth import get_user_model
import logging

user = get_user_model()
logger = logging.getLogger(__name__)


@shared_task
def create_user(email, payload):
    try:
        user_data, created = user.objects.get_or_create(email=email, defaults={'first_name': payload['given_name'],
                                                                               'last_name': payload['family_name'],
                                                                               'username': email})
        return user_data
    except Exception as e:
        logger.error(f"Failed to create user: {e}")
        return None
