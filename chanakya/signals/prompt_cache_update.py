from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from chanakya.models.prompts_model import PromptsModel
from django.contrib.auth import get_user_model
from django.core.cache import cache
from chanakya.models.conversation import ConversationModel
from chanakya.models.subscription_model import UserSubscription

user = get_user_model()


@receiver(post_save, sender=PromptsModel)
def handle_prompt_updated(sender, instance, created, **kwargs):
    if not created:
        instance.update_cache()


@receiver(post_save, sender=user)
def clear_user_cache(sender, instance, **kwargs):
    cache_key = instance.email
    cache.delete(cache_key)


@receiver(post_delete, sender=user)
def clear_user_cache_on_delete(sender, instance, **kwargs):
    cache_key = instance.email
    cache.delete(cache_key)


@receiver(post_save, sender=ConversationModel)
def update_conversation_cache(sender, instance, **kwargs):
    conversation_id = instance.id
    cache_key = f"conversation_{conversation_id}"
    cache.delete(cache_key)


# for conversation history management
@receiver(post_save, sender=ConversationModel)
def update_conversation_cache(sender, instance, **kwargs):
    user_id = instance.user_id
    cache_key = f"conversation_{user_id}"
    cache.delete(cache_key)


@receiver(post_delete, sender=ConversationModel)
def clear_conversation_cache(sender, instance, **kwargs):
    conversation_id = instance.id
    cache_key = f"conversation_{conversation_id}"
    cache.delete(cache_key)


@receiver(post_save, sender=UserSubscription)
@receiver(post_delete, sender=UserSubscription)
def clear_user_cache(sender, instance, **kwargs):
    user_email_cache_key = f"user_subscription_data_{instance.user.id}"
    user_status_cache_key = f"subscription_status_{instance.user.id}"
    cache.delete(user_email_cache_key)
    cache.delete(user_status_cache_key)
