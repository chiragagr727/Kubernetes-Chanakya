"""
WSGI config for chanakya_backend project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/howto/deployment/wsgi/
"""

import os
from django.core.wsgi import get_wsgi_application
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve(strict=True).parent.parent
sys.path.append(str(BASE_DIR / "chanakya"))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'chanakya_backend.settings.development')

application = get_wsgi_application()
