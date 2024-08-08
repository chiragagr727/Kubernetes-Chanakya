from celery import shared_task
from django.core.cache import cache
from chanakya.models.conversation import MessageModel, ConversationModel
from chanakya.utils.title_generator import ConversationTitleGenerator
import logging

logger = logging.getLogger(__name__)

@shared_task
def generate_conversation_title(conversation_id,conversation_history):
    try:
        conversation = ConversationModel.objects.get(id=conversation_id)
        title = ConversationTitleGenerator().generate_title(conversation=conversation_history)
        conversation.title = title
        conversation.save()
        logger.info("Conversation title saved successfully")
    except ConversationModel.DoesNotExist:
        logger.error(f"Conversation with id {conversation_id} does not exist")
