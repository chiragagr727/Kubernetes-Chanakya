import os
from mixpanel import Mixpanel
from chanakya.utils import sentry
import logging

mp = Mixpanel(os.environ.get("MIXPANEL_TOKEN"))
logger = logging.getLogger(__name__)


def log_and_report_error(event, user_sub_id, exception):
    error_message = f"Error tracking {event} for user {user_sub_id}: {exception}"
    sentry.capture_exception(message=error_message, exception=exception)
    logger.error(error_message)


def _track_signup(user_sub_id, payload):
    event = "Sign Up"
    try:
        mp.track(user_sub_id, event)
        mp.people_set(user_sub_id, payload)
    except Exception as e:
        log_and_report_error(event, user_sub_id, e)


def _track_user_event(user_sub_id):
    event = "Get User"
    try:
        mp.track(user_sub_id, event)
    except Exception as e:
        log_and_report_error(event, user_sub_id, e)


def _track_update_user_events(user_sub_id, data):
    event = "Update User"
    try:
        mp.people_set(user_sub_id, data)
        mp.track(user_sub_id, event)
    except Exception as e:
        log_and_report_error(event, user_sub_id, e)


def _delete_user_event(user_sub_id):
    event = "User Deactivated"
    try:
        mp.track(user_sub_id, event)
        mp.people_set(user_sub_id, {"is_active": False})
    except Exception as e:
        log_and_report_error(event, user_sub_id, e)


def _create_conversation(user_sub_id):
    event = "Created Conversation"
    try:
        mp.track(user_sub_id, event)
    except Exception as e:
        log_and_report_error(event, user_sub_id, e)


def _chat_with_chanakya(user_sub_id):
    event = "Chat With AI Chanakya"
    try:
        mp.track(user_sub_id, event)
    except Exception as e:
        log_and_report_error(event, user_sub_id, e)


def _chat_with_google_search(user_sub_id):
    event = "Chat With Google WebSearch"
    try:
        mp.track(user_sub_id, event)
    except Exception as e:
        log_and_report_error(event, user_sub_id, e)


def _chat_without_web_search(user_sub_id):
    event = "Chat Without WebSearch"
    try:
        mp.track(user_sub_id, event)
    except Exception as e:
        log_and_report_error(event, user_sub_id, e)
