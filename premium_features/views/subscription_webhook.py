import logging
import os
from rest_framework.views import APIView
from rest_framework.response import Response
from chanakya.models.subscription_model import UserSubscription
from chanakya.utils import custom_exception
from django.contrib.auth import get_user_model
from django.shortcuts import redirect
from chanakya.tasks.push_notification import PushNotification
import datetime
from django.db import transaction

logger = logging.getLogger(__name__)
User = get_user_model()


class SubScriptionWebhook(APIView):

    def post(self, request):
        try:
            logger.info("************** Google Play Webhook ***********************")
            payload = request.data
            logger.debug(f"Webhook request data:\n {payload}")
            logger.debug(f"Webhook headers:\n {request.headers}")
            authorization = request.headers.get("Authorization")
            auth_key = os.environ.get("AUTHORIZATION_FOR_WEBHOOK")
            if authorization != auth_key:
                return redirect("/400/")
            event_response = payload.get('event', {})
            event_type = event_response.get('type', '')
            request_id = event_response.get('id', '')
            self.check_aliases_id(request_id)
            logger.debug(f"Event type: {event_type}")
            notification = PushNotification()
            if event_type == 'INITIAL_PURCHASE':
                self.handle_initial_purchase(event_response, request_id, notification)
            elif event_type == 'RENEWAL':
                self.handle_renewal(event_response, request_id, notification)
            elif event_type == 'CANCELLATION':
                self.handle_cancellation(event_response, notification)
            elif event_type == "SUBSCRIPTION_PAUSED":
                self.handle_subscription_paused(event_response, notification)
            elif event_type == "EXPIRATION":
                self.handle_expiration(event_response, notification)
            return Response({'message': 'Event received'}, status=200)
        except Exception as e:
            logger.error(f"Error processing webhook: {e}")
            return Response({'message': 'Bad Request'}, status=404)

    def check_aliases_id(self, request_id):
        if UserSubscription.objects.filter(request_id=request_id).exists():
            logger.error("Request already exists in initial purchase event")
            raise custom_exception.DataAlreadyExist("Duplicate Request")
        return True

    @transaction.atomic
    def handle_initial_purchase(self, event_response, request_id, notification):
        try:
            subscriber_attributes = event_response.get('subscriber_attributes', {})
            email_info = subscriber_attributes.get('$email', {})
            user_email = email_info.get('value', '')
            provider_type = event_response["store"]
            event_type = event_response.get("type")
            transaction_id = event_response.get("transaction_id")
            period_type = event_response.get("period_type")

            logger.info(f"User: {subscriber_attributes}")
            logger.info(f"User email: {user_email}")
            logger.info(f"Email: {email_info}")
            logger.info(f"Provider type: {provider_type}")

            if not user_email:
                logger.error("User email not found in initial purchase event")
                raise custom_exception.DataNotFound("User Not Found")

            logger.info(f"Initial purchase handled for user {user_email}")
            user = User.objects.get(email=user_email)
            event_timestamp_ms = datetime.datetime.fromtimestamp(event_response["event_timestamp_ms"] / 1000).strftime(
                '%Y-%m-%d %H:%M:%S')
            expiration_at_ms = datetime.datetime.fromtimestamp(event_response["expiration_at_ms"] / 1000).strftime(
                '%Y-%m-%d %H:%M:%S')
            UserSubscription.objects.filter(user=user, active=True).update(active=False)

            UserSubscription.objects.create(
                user=user,
                request_id=request_id,
                type=event_type,
                transaction_id=transaction_id,
                period_type=period_type,
                provider_type=provider_type,
                start_date=event_timestamp_ms,
                expiry_date=expiration_at_ms,
                active=True
            )

            user.is_subscription_active = True
            user.save()
            notification.send_notification_to_user(
                contents="🎉 Welcome! Your subscription is now active 🎉", user_player_id=str(user.id))
            logger.info(f"Initial purchase handled for user {user.email}")
            return True
        except Exception as e:
            logger.error(f"Error handling initial purchase: {e}")
            raise custom_exception.InvalidRequest(f"Error handling initial purchase: {e}")

    @transaction.atomic
    def handle_renewal(self, event_response, request_id, notification):
        try:
            subscriber_attributes = event_response.get('subscriber_attributes', {})
            email_info = subscriber_attributes.get('$email', {})
            user_email = email_info.get('value', '')
            provider_type = event_response["store"]

            event_type = event_response.get("type")
            transaction_id = event_response.get("transaction_id")
            period_type = event_response.get("period_type")

            logger.info(f"User: {subscriber_attributes}")
            logger.info(f"User email: {user_email}")
            logger.info(f"Email: {email_info}")
            logger.info(f"Provider type: {provider_type}")

            if not user_email:
                logger.error("User email not found in renewal event")
                raise custom_exception.DataNotFound("User Not Found")

            event_timestamp_ms = datetime.datetime.fromtimestamp(event_response["event_timestamp_ms"] / 1000).strftime(
                '%Y-%m-%d %H:%M:%S')
            expiration_at_ms = datetime.datetime.fromtimestamp(event_response["expiration_at_ms"] / 1000).strftime(
                '%Y-%m-%d %H:%M:%S')

            user = User.objects.get(email=user_email)
            UserSubscription.objects.filter(user=user, active=True).update(active=False)

            UserSubscription.objects.create(
                user=user,
                request_id=request_id,
                type=event_type,
                transaction_id=transaction_id,
                period_type=period_type,
                provider_type=provider_type,
                start_date=event_timestamp_ms,
                expiry_date=expiration_at_ms,
                active=True
            )

            user.is_subscription_active = True
            user.save()
            notification.send_notification_to_user(
                contents="🔄 Your subscription has been renewed 🔄",
                user_player_id=str(user.id))
            logger.info(f"Renewal handled for user {user.email}")
            return True
        except Exception as e:
            logger.error(f"Error handling renewal: {e}")
            raise custom_exception.InvalidRequest(f"Error handling renewal: {e}")

    @transaction.atomic
    def handle_cancellation(self, event_response, notification):
        try:
            subscriber_attributes = event_response.get('subscriber_attributes', {})
            email_info = subscriber_attributes.get('$email', {})
            user_email = email_info.get('value', '')

            if not user_email:
                logger.error("User email not found in cancellation event")
                raise custom_exception.DataNotFound("User Not Found")

            logger.info(f"User: {subscriber_attributes}")
            logger.info(f"User email: {user_email}")
            logger.info(f"Email: {email_info}")

            user = User.objects.get(email=user_email)
            UserSubscription.objects.filter(user=user, active=True).update(subscription_cancel=True)
            logger.info(f"Cancellation handled for user {user.email}")
            notification.send_notification_to_user(
                contents="⚠️ Your subscription has been cancelled ⚠️",
                user_player_id=str(user.id))
            return True
        except Exception as e:
            logger.error(f"Error handling cancellation: {e}")
            raise custom_exception.InvalidRequest(f"Error handling cancellation: {e}")

    @transaction.atomic
    def handle_subscription_paused(self, event_response, notification):
        try:
            subscriber_attributes = event_response.get('subscriber_attributes', {})
            email_info = subscriber_attributes.get('$email', {})
            user_email = email_info.get('value', '')

            logger.info(f"User: {subscriber_attributes}")
            logger.info(f"User email: {user_email}")
            logger.info(f"Email: {email_info}")

            if not user_email:
                logger.error("User email not found in subscription paused event")
                raise custom_exception.DataNotFound("User Not Found")

            logger.info(f"Subscription paused for user {user_email}")
            user = User.objects.get(email=user_email)
            UserSubscription.objects.filter(user=user, active=True).update(subscription_paused=True)
            logger.info(f"Subscription paused for user {user.email}")
            notification.send_notification_to_user(
                contents="⏸️ Your subscription has been paused ⏸️",
                user_player_id=str(user.id))
            return True
        except Exception as e:
            logger.error(f"Error handling subscription paused: {e}")
            raise custom_exception.InvalidRequest(f"Error handling subscription paused: {e}")

    @transaction.atomic
    def handle_expiration(self, event_response, notification):
        try:
            subscriber_attributes = event_response.get('subscriber_attributes', {})
            email_info = subscriber_attributes.get('$email', {})
            user_email = email_info.get('value', '')

            logger.info(f"User: {subscriber_attributes}")
            logger.info(f"User email: {user_email}")
            logger.info(f"Email: {email_info}")

            if not user_email:
                logger.error("User email not found in expiration event")
                raise custom_exception.DataNotFound("User Not Found")

            logger.info(f"Subscription expired for user {user_email}")
            user = User.objects.get(email=user_email)
            UserSubscription.objects.filter(user=user, active=True).update(subscription_expire=True)
            logger.info(f"Subscription expired for user {user.email}")
            user.is_subscription_active = False
            user.save()
            notification.send_notification_to_user(
                contents="⚠️ Your subscription has expired ⚠️",
                user_player_id=str(user.id))
            return True
        except Exception as e:
            logger.error(f"Error handling expiration: {e}")
            raise custom_exception.InvalidRequest(f"Error handling expiration: {e}")
