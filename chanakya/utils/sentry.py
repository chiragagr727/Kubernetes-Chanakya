import logging
import sentry_sdk
import os
from sentry_sdk.integrations.logging import LoggingIntegration

sentry_logging = LoggingIntegration(
    level=logging.ERROR,
    event_level=logging.ERROR
)

sentry_sdk.init(
    dsn=os.environ.get("SENTRY_DSN"),
    integrations=[sentry_logging]
)


def capture_error(message, user_email, exception):
    try:
        raise exception
    except Exception as e:
        logging.error(message, extra={"user_email": user_email, "exception": e})


def capture_error_for_mini_io(message, mini_io_host, exception):
    try:
        raise exception
    except Exception as e:
        logging.error(message, extra={"mini_io_host": mini_io_host, "exception": e})


def model_error(message, user_email, content):
    logging.error(message, extra={"user_email": user_email, "response_content": content})


def capture_exception(message, exception):
    try:
        raise exception
    except Exception as e:
        logging.error(message, extra={"exception": e})
