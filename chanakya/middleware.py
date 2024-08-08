import json
import os
import requests
import random
from datetime import datetime
from jose import jwt, JWTError, ExpiredSignatureError
from rest_framework import status
from django.http import HttpResponse
from django.contrib.auth import get_user_model
import logging
from django.core.cache import cache
from jwt.algorithms import RSAAlgorithm
from django.shortcuts import redirect
from django.utils.deprecation import MiddlewareMixin
# from chanakya.tasks.middleware_task import create_user
from chanakya.utils import sentry
from chanakya.utils.mixpanel import _track_signup

user = get_user_model()
logger = logging.getLogger(__name__)


class RequestIdMiddleware(MiddlewareMixin):
    def process_request(self, request):
        request.request_id = str(datetime.now().strftime("%Y%m%d%H%M%S%f") + str(random.randint(0, 100)))
        return None

    def process_response(self, request, response):
        response['requestId'] = request.request_id
        return response


def generate_response(message, detail, status_code):
    response_content = json.dumps({'message': message, 'detail': detail, 'status_code': status_code})
    return HttpResponse(response_content, content_type='application/json', status=status_code)


class AuthenticationValidation:
    EXEMPT_URLS = ['/admin/', '/chanakya_backend/static/', '/__debug__/', '/api/', '/staticfiles/',
                   '/static/', '/chanakya_backend/media/', '/chanakya_backend/staticfiles/', '/400/',
                   '/403/', '/chanakya/debugger/', '/chanakya/temporary/chat/',
                   '/subscription/webhook/', '/chanakya/suggestions/']

    def __init__(self, get_response):
        self.get_response = get_response
        self.jwks_url = os.environ.get('JWK_URL')
        self.issuer = os.environ.get('ISSUER')
        self.audience = os.environ.get('AUDIENCE')
        self.algorithms = os.environ.get('ALGORITHM')

    def __call__(self, request):
        for exempt_url_prefix in self.EXEMPT_URLS:
            if request.path.startswith(exempt_url_prefix):
                return self.get_response(request)
        auth_token = request.headers.get('Authorization', None)
        if not auth_token:
            return redirect("/400/")
        if not auth_token.startswith('Bearer '):
            return generate_response('Unauthorized', 'Invalid Api Key', status.HTTP_403_FORBIDDEN)
        if not self.jwks_url:
            return generate_response('Unauthorized', 'JWK is missing. Contact Admin', status.HTTP_403_FORBIDDEN)
        try:
            auth_token = auth_token.split()[1]
            header = jwt.get_unverified_header(auth_token)
            kid = header['kid']
            payload = self.decode_jwt(auth_token, kid)
            user_data = self.get_or_create_user(payload)
            request.META["email"] = payload.get('email')
            request.META["sub"] = payload.get("sub")
            request.META["user"] = user_data
        except IndexError:
            return generate_response('Unauthorized', 'Token format is invalid.', status.HTTP_403_FORBIDDEN)
        except ExpiredSignatureError:
            return generate_response('Unauthorized', 'Token has expired.', status.HTTP_403_FORBIDDEN)
        except JWTError as e:
            return generate_response('Unauthorized', str(e), status.HTTP_403_FORBIDDEN)
        except Exception as e:
            return generate_response('Unauthorized', f"Invalid Token", status.HTTP_403_FORBIDDEN)
        return self.get_response(request)

    def get_jwks(self):
        jwks = cache.get(self.jwks_url)
        if not jwks:
            response = requests.get(self.jwks_url)
            response.raise_for_status()
            jwks = response.json()
            cache.set(self.jwks_url, jwks, 2 * 24 * 60 * 60)
        return jwks

    def decode_jwt(self, token, kid):
        # Check if token is cached
        cached_token = cache.get(token)
        if cached_token:
            return cached_token

        jwks = self.get_jwks()
        key = next((item for item in jwks['keys'] if item['kid'] == kid), None)
        if not key:
            return generate_response('Unauthorized', f"Invalid Token: Public Key Not Found",
                                     status.HTTP_403_FORBIDDEN)

        try:
            rsa_key = RSAAlgorithm.from_jwk(key)
            decoded_token = jwt.decode(token, rsa_key, algorithms=self.algorithms, audience=self.audience,
                                       issuer=self.issuer)
            # Cache the decoded token
            cache.set(token, decoded_token, 2 * 60 * 60)  # Cache for 2 hours
            return decoded_token
        except jwt.JWTError as e:
            raise Exception(f"{str(e)}")
        except Exception as e:
            raise Exception(f"{str(e)}")

    def get_or_create_user(self, payload):
        logger.debug("User Record")
        try:
            email = payload.get('email')
            logger.info(f"user email: {email}")
            # Check if user is cached
            cached_user = cache.get(email)
            if cached_user:
                return cached_user

            given_name = payload.get("given_name", None)
            last_name = payload.get("family_name", None)
            if not last_name:
                last_name = payload.get("nickname")
            if not email:
                raise Exception('Email not found in token payload')

            try:
                if given_name and last_name:
                    user_data, created = user.objects.get_or_create(email=email,
                                                                    defaults={'first_name': given_name,
                                                                              'last_name': last_name,
                                                                              'username': email})
                else:
                    user_data, created = user.objects.get_or_create(email=email, defaults={'username': email})

                if created:
                    user_sub_id = payload.get("sub")
                    _track_signup(user_sub_id, payload)

            except Exception as e:
                sentry.capture_error(message="Failed to  save user record", user_email=payload.get('email'),
                                     exception=e)
                raise Exception('User Not Found')

                # Offload user creation to Celery (Optional)
                # user_data = create_user.delay(email, payload).get(timeout=10)

            # Cache the user data
            if user_data:
                cache.set(email, user_data, 2 * 60 * 60)

            return user_data
        except Exception as e:
            sentry.capture_error(message="Failed to retrieve or save user record", user_email=payload.get('email'),
                                 exception=e)
            raise Exception(f'Failed to retrieve or save user record: {e}')


class AdminAuthenticationMiddleware:
    ADMIN_ONLY_URLS = ['/chanakya/debugger/']

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path in self.ADMIN_ONLY_URLS and not request.user.is_superuser:
            return redirect("/403/")
        return self.get_response(request)
