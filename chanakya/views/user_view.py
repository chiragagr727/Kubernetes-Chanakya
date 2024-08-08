from rest_framework import viewsets, status
from rest_framework.decorators import action
import os
import http.client
import ssl
import certifi
from chanakya.utils import custom_exception
from chanakya.serializer.user_serializer import UserSerializer, UserUpdateSerializer
from django.contrib.auth import get_user_model
from rest_framework.response import Response
import logging
import requests
import http.client
import json
from chanakya.views.conversation_retrieve import RetrieveConversationData
from chanakya.utils.e2e_network_bucket import upload_file_in_mini_io
from django.shortcuts import render
from chanakya.utils import mixpanel

User = get_user_model()
logger = logging.getLogger(__name__)


class UserViewSet(viewsets.ViewSet):

    @action(detail=False, methods=['GET'], url_path='get-user')
    def get_user(self, request):
        user = request.META.get("user", None)
        auth_user_id = request.META.get("sub", None)
        logger.debug(f"GET API USER Email: {user}")
        logger.debug(f"GET USER REQUEST: {request.data}")
        if not user:
            return Response({"status": False}, status=status.HTTP_200_OK)
        if not user.is_active:
            return Response({"status": False}, status=status.HTTP_200_OK)
        serializer = UserSerializer(user)
        mixpanel._track_user_event(auth_user_id)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['POST'], url_path='update-user')
    def update_user_post(self, request):
        user = request.META.get("user", None)
        auth_user_id = request.META.get("sub", None)
        logger.debug(f"GET API USER Email: {user}")
        logger.debug(f"GET USER REQUEST: {request.data}")
        if not user:
            return Response({"status": False}, status=status.HTTP_200_OK)
        serializer = UserUpdateSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            data = serializer.data
            data["email"] = user.email
            mixpanel._track_update_user_events(auth_user_id, request.data)
            return Response(data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['DELETE'], url_path='delete-user')
    def deactivate_user_post(self, request, email=None):
        user = request.META.get("user", None)
        auth_user_id = request.META.get("sub", None)
        logger.debug(f"GET API USER Email: {user}")
        logger.debug(f"GET USER REQUEST: {request.data}")
        auth_audience = os.environ.get("AUTH_AUDIENCE")
        auth_domain = os.environ.get("AUTH_DOMAIN")
        auth_client_id = os.environ.get("AUTH_CLIENT_ID")
        auth_client_secret = os.environ.get("AUTH_CLIENT_SECRET")
        if not user:
            return Response({"status": False}, status=status.HTTP_200_OK)
        try:
            logger.info("************* User Deleted attempt ****************")
            token = self.generate_access_token(auth_audience, auth_domain, auth_client_id, auth_client_secret)
            access_token = token.get("access_token")
            url = f"https://{auth_domain}/api/v2/users/{auth_user_id}"
            headers = {'Authorization': f"Bearer {access_token}"}
            response = requests.delete(url=url, headers=headers)
            if response.status_code == 204:
                fetch_conversation_data = RetrieveConversationData()
                user_data = fetch_conversation_data.retrieve_by_user(user)
                if user_data is not None:
                    base_folder = os.environ.get("FOLDER_NAME_FOR_USER_CHAT")
                    file_name = f"user_{user.email}_{user.id}.json"
                    with open(file_name, 'w') as temp_file:
                        temp_file.write(user_data)
                    with open(file_name, 'rb') as temp_file:
                        url = upload_file_in_mini_io(base_folder=base_folder, file=temp_file, file_name=file_name,
                                                     user=user)
                    os.remove(file_name)
                    logger.debug(f"user conversation url: {url}")
                    mixpanel._delete_user_event(auth_user_id)
                user.delete()
                return Response({"message": "User has been deleted successfully"}, status=status.HTTP_200_OK)
            return Response({"message": response.text}, status=response.status_code)
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def generate_access_token(self, auth_audience, auth_domain, auth_client_id, auth_client_secret):
        try:
            context = ssl.create_default_context(cafile=certifi.where())
            conn = http.client.HTTPSConnection(auth_domain, context=context)
            headers = {'content-type': "application/json"}
            payload = json.dumps({
                "client_id": auth_client_id,
                "client_secret": auth_client_secret,
                "audience": auth_audience,
                "grant_type": "client_credentials"
            })
            conn.request("POST", "/oauth/token", payload, headers)
            res = conn.getresponse()
            data = res.read()
            decode_res = json.loads(data.decode("utf-8"))
            access_token = decode_res.get("access_token", None)
            expires_in = decode_res.get("expires_in", None)
            if not access_token:
                raise custom_exception.InvalidData("Token Not Found, Request Again.")
            return {"access_token": access_token, "expiry_in": expires_in}
        except Exception as e:
            raise custom_exception.InvalidRequest(f"Failed to generate token: {str(e)}")
