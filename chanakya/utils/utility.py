import secrets
import string
import os
import base64
from datetime import timedelta
import requests
from django.utils import timezone
from chanakya.models.conversation import MessageModel
from django.core.cache import cache
from chanakya.utils import custom_exception
from chanakya.models.prompts_model import PromptsModel
from chanakya.enums.role_enum import RoleEnum
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from chanakya.utils import sentry
import logging

logger = logging.getLogger(__name__)

DEFAULT_PROMPT_NAME = os.getenv("DEFAULT_PROMPT_NAME")
DEFAULT_IOS_PROMPT_NAME = os.getenv("DEFAULT_IOS_PROMPT_NAME")


def check_rate_limit_of_conversation(user, rate_limit, time_limit):
    TIME_FRAME = timedelta(minutes=time_limit)
    now = timezone.now()
    start_time = now - TIME_FRAME
    message_count = MessageModel.objects.filter(conversation__user=user, created__gte=start_time,
                                                role=RoleEnum.USER.value).count()
    if message_count >= rate_limit:
        raise custom_exception.RateLimitExceed(
            f"Rate limit exceeded: Only {rate_limit} messages allowed per {TIME_FRAME.total_seconds() / 60} minute(s).")


def generate_unique_char(length):
    api_key_characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(api_key_characters) for _ in range(length))


# Function to build the prompt
def get_prompt_instance(is_ios=False):
    if is_ios:
        prompt_instance = cache.get(DEFAULT_IOS_PROMPT_NAME)
        logger.info(f"prompt cache: {prompt_instance}")
        if prompt_instance is None:
            try:
                logger.info(f"prompt module: {DEFAULT_IOS_PROMPT_NAME}")
                prompt_instance = PromptsModel.objects.get(name=DEFAULT_IOS_PROMPT_NAME)
                logger.info(f"prompt ios instance: {prompt_instance}")
                cache.set(DEFAULT_IOS_PROMPT_NAME, prompt_instance, timeout=60 * 60 * 720)
            except Exception as e:
                raise custom_exception.InvalidData("Prompt Model Not Found")
        return prompt_instance
    prompt_instance = cache.get(DEFAULT_PROMPT_NAME)

    if prompt_instance is None:
        try:
            prompt_instance = PromptsModel.objects.get(name=DEFAULT_PROMPT_NAME)
            cache.set(DEFAULT_PROMPT_NAME, prompt_instance, timeout=60 * 60 * 720)
        except Exception as e:
            raise custom_exception.InvalidData("Prompt Model Not Found")
    return prompt_instance


def get_prompt_instance_for_gs(model_name):
    prompt_instance = cache.get(model_name)
    if prompt_instance is None:
        try:
            prompt_instance = PromptsModel.objects.get(name=model_name)
            cache.set(model_name, prompt_instance, timeout=60 * 60 * 720)
        except Exception as e:
            raise custom_exception.InvalidData("Prompt Model Not Found")
    return prompt_instance


def build_prompt_and_get_conversation_history(conversation, query, prompt_builder):
    try:
        messages = MessageModel.objects.filter(conversation=conversation).order_by("updated")[:4]
    except Exception as e:
        messages = ""
    conversation_history = [{"role": msg.role, "content": msg.content} for msg in messages]
    # logger.debug(f"in chanakya_chat.build_prompt() conversation history:\n{conversation_history}")
    # logger.info(f"*************************************")
    return prompt_builder.build_prompt(conversation_history=conversation_history,
                                       user_question=query), conversation_history


class SendRequestForTogetherStreaming:
    def __init__(self, model, temperature, top_p, top_k, max_tokens, repetition_penalty, stop):
        self._model = model
        self._temperature = temperature
        self._top_p = top_p
        self._top_k = top_k
        self._max_tokens = max_tokens
        self._repetition_penalty = repetition_penalty
        self._stop = stop

    def __call__(self, together_api_token, prompt, url):
        payload = {
            "model": self._model,
            "prompt": str(prompt),
            "temperature": self._temperature,
            "top_p": self._top_p,
            "top_k": self._top_k,
            "max_tokens": self._max_tokens,
            "repetition_penalty": self._repetition_penalty,
            "stream": True,
            "stream_tokens": True,
            "type": "chat",
            "stop": self._stop,
        }
        headers = {
            "Authorization": f"Bearer {together_api_token}",
            "Accept": "text/event-stream",
            "Content-Type": "application/json"
        }
        try:
            upstream_response = requests.post(url, json=payload, headers=headers, stream=True)
            upstream_response.raise_for_status()
            return upstream_response
        except requests.exceptions.HTTPError as http_err:
            logger.debug(f"payload of together api \n {payload}")
            sentry.capture_error(message="http error while sending request", user_email="temporary_chat",
                                 exception=http_err)
            raise custom_exception.InvalidRequest("401 Client Error")
        except requests.exceptions.RequestException as req_err:
            logger.debug(f"payload of together api \n {payload}")
            sentry.capture_error(message="http error while sending request", user_email="temporary_chat",
                                 exception=req_err)
            raise custom_exception.InvalidRequest("404 Request Error")


class SendRequestForTogetherStreamingIOS:
    def __init__(self, model, temperature, top_p, top_k, max_tokens, repetition_penalty, stop):
        self._model = model
        self._temperature = temperature
        self._top_p = top_p
        self._top_k = top_k
        self._max_tokens = max_tokens
        self._repetition_penalty = repetition_penalty
        self._stop = stop

    def __call__(self, together_api_token, prompt, url):
        payload = {
            "model": self._model,
            "prompt": str(prompt),
            "temperature": self._temperature,
            "top_p": self._top_p,
            "top_k": self._top_k,
            "max_tokens": self._max_tokens,
            "repetition_penalty": self._repetition_penalty,
            "stream": True,
            "stream_tokens": True,
            "type": "chat",
            "stop": self._stop,
            "safety_model": "meta-llama/Meta-Llama-Guard-3-8B",
        }
        headers = {
            "Authorization": f"Bearer {together_api_token}",
            "Accept": "text/event-stream",
            "Content-Type": "application/json"
        }
        try:
            upstream_response = requests.post(url, json=payload, headers=headers, stream=True)
            upstream_response.raise_for_status()
            return upstream_response
        except requests.exceptions.HTTPError as http_err:
            logger.debug(f"payload of together api \n {payload}")
            sentry.capture_error(message="http error while sending request", user_email="temporary_chat",
                                 exception=http_err)
            raise custom_exception.InvalidRequest("401 Client Error")
        except requests.exceptions.RequestException as req_err:
            logger.debug(f"payload of together api \n {payload}")
            sentry.capture_error(message="http error while sending request", user_email="temporary_chat",
                                 exception=req_err)
            raise custom_exception.InvalidRequest("404 Request Error")


class EncryptionDecryption:

    def __init__(self, fernet_key):
        self.fernet_key = fernet_key

    def decrypt(self, hash_prompt):
        try:
            key = base64.b64decode(self.fernet_key)
            encrypted_api_key = base64.b64decode(hash_prompt)
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted_api_key = unpad(cipher.decrypt(encrypted_api_key), AES.block_size).decode()
            return decrypted_api_key
        except Exception as e:
            raise custom_exception.InvalidRequest(f"Failed to decrypt: {e}")
