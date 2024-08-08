from chanakya_backend.settings.base import *
from chanakya_backend.settings.base import INSTALLED_APPS
from chanakya_backend.settings.base import MIDDLEWARE
import environ
import django.db.models.signals
import sentry_sdk
from sentry_sdk.integrations.django import DjangoIntegration

env = environ.Env()
environ.Env.read_env()

SECRET_KEY = env("DJANGO_SECRET_KEY")

DEBUG = env.bool("DEBUG_FOR_PROD", default=False)

ADMIN_URL = env("ADMIN_URL")

ALLOWED_HOSTS = env.list("ALLOWED_HOSTS")

CORS_ALLOWED_ORIGINS = env.list("ALLOWED_ORIGIN")

CORS_ORIGIN_ALLOW_ALL = False
CORS_ALLOW_ALL_ORIGINS = False

# CSRF_TRUSTED_ORIGINS = env.list("ALLOWED_ORIGIN")


CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'origin',
    'Content-Type',
    'Cache-Control',
    'Connection',
    'cache-control',
    'x-requested-with'
]

CORS_ALLOW_METHODS = [
    'DELETE',
    'GET',
    'POST',
    'PUT',
    'PATCH',
]

SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

INSTALLED_APPS += [
    "django_extensions"
]

SPECTACULAR_SETTINGS = {
    "TITLE": "Chanakya API",
    "DESCRIPTION": "Documentation of API endpoints of chanakya",
    "VERSION": "1.0.0",
    "SERVE_PERMISSIONS": ["rest_framework.permissions.AllowAny"],
    'SERVE_AUTHENTICATION': [],
    "SCHEMA_PATH_PREFIX": "/api/",
}

REST_FRAMEWORK = {
    "EXCEPTION_HANDLER": "chanakya.utils.exception_handler.custom_exception_handler",
    'DEFAULT_FILTER_BACKENDS': (
        'django_filters.rest_framework.DjangoFilterBackend',
    ),
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
        'rest_framework.parsers.MultiPartParser',
    ],
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',  # Add this line
}
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{levelname} {asctime} {module} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "file": {
            "level": "DEBUG",
            "class": "logging.FileHandler",
            "filename": "debug.log",
            "formatter": "verbose",
        },
        "console": {
            "level": "DEBUG",
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "loggers": {
        "": {  # Root logger
            "handlers": ["file", "console"],
            "level": "DEBUG",
            "propagate": True,
        },
        "django": {
            "handlers": ["file"],
            "level": "INFO",  # Adjust this as needed
            "propagate": False,
        },
        # Explicit logger for your application's module
        "history.views": {
            "handlers": ["file", "console"],
            "level": "DEBUG",
            "propagate": False,
        },
    },
}

# Email Configuration
EMAIL_BACKEND = env('EMAIL_BACKEND')
EMAIL_HOST = env('EMAIL_HOST')
EMAIL_PORT = env('EMAIL_PORT')
EMAIL_USE_TLS = env('EMAIL_USE_TLS')
EMAIL_HOST_USER = env('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = env('DEFAULT_FROM_EMAIL')

# Admins to receive error notifications
ADMINS = [(admin.split()[0], admin.split()[1].strip('<>')) for admin in env('ADMINS').split(',')]

sentry_sdk.init(
    dsn="https://8aa4999ebb8147e5727f13e2502fdf25@o4507445795487744.ingest.de.sentry.io/4507445811282000",
    # Set traces_sample_rate to 1.0 to capture 100%
    # of transactions for tracing.
    traces_sample_rate=1.0,
    # Set profiles_sample_rate to 1.0 to profile 100%
    # of sampled transactions.
    # We recommend adjusting this value in production.
    profiles_sample_rate=1.0,

    integrations=[
        DjangoIntegration(
            transaction_style='url',
            middleware_spans=True,
            signals_spans=True,
            signals_denylist=[
                django.db.models.signals.pre_init,
                django.db.models.signals.post_init,
            ],
            cache_spans=False,
        ),
    ],
)
