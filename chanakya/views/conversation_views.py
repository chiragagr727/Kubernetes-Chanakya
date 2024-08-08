from rest_framework import viewsets, status
from rest_framework.response import Response
from chanakya.models.conversation import ConversationModel, MessageModel, FeedbackModel
from chanakya.serializer.conversaton_serializer import ConversationSerializer
from chanakya.utils.custom_exception import CustomException
import logging
from chanakya.utils import custom_exception
from chanakya.enums.role_enum import RoleEnum
from django.core.cache import cache
from django.db.models.signals import post_save
from django.dispatch import receiver

logger = logging.getLogger(__name__)
logger.debug("Starting the Application")


class ConversationViewSet(viewsets.ViewSet):

    def list(self, request):
        """
        List all conversations for the authenticated user.
        """

        user = request.META["user"]
        cache_key = f"conversation_{user.id}"
        cached_data = cache.get(cache_key)

        if cached_data:
            return Response(cached_data)

        if user is None:
            raise CustomException(message="No user Found", status_code=404)

        conversations = ConversationModel.objects.filter(user=user).prefetch_related('messages').order_by('-updated')
        serializer = ConversationSerializer(conversations, many=True, context={'request': request})
        data = serializer.data
        cache.set(cache_key, data, timeout=3600)
        return Response(data)

    def retrieve(self, request, pk=None):
        """
        Retrieve a specific conversation by ID, including its messages.
        """

        try:
            user = request.META.get("user")
            if user is None:
                raise CustomException(message="No user Found", status_code=404)

            conversation = ConversationModel.objects.prefetch_related('messages').get(pk=pk, user=user)
            serializer = ConversationSerializer(conversation, context={'request': request, 'view': self})

            return Response(serializer.data)
        except ConversationModel.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)


class ChanakyaChatFeedback(viewsets.ViewSet):

    def create(self, request):
        conversation_id = request.data.get('conversation')
        feedback_text = request.data.get('feedback')
        category = request.data.get('category')

        if not feedback_text:
            raise CustomException(message="Feedback is required", status_code=400)

        try:
            latest_message = MessageModel.objects.filter(conversation_id=conversation_id,
                                                         role=RoleEnum.ASSISTANT.value).latest('created')

            if FeedbackModel.objects.filter(message=latest_message).exists():
                raise custom_exception.DataAlreadyExist("Feedback has already been provided for this message.")

            FeedbackModel.objects.create(
                message=latest_message,
                feedback=feedback_text,
                category=category,
                is_unliked=True
            )

            return Response({"message": "Feedback Marked"}, status=status.HTTP_201_CREATED)

        except MessageModel.DoesNotExist:
            raise custom_exception.DataNotFound("Message not found for this conversation and role.")
