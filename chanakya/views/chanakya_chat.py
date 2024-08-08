import logging
import os
import json
from rest_framework.views import APIView
from django.http import StreamingHttpResponse
from chanakya.enums.role_enum import RoleEnum
from chanakya.tasks.title_generator_task import generate_conversation_title
from chanakya.utils import custom_exception, title_generator
from chanakya.models.conversation import ConversationModel, MessageModel
from django.shortcuts import redirect
from chanakya.utils.prompt_builder import PromptBuilder
from django.core.cache import cache
from chanakya.serializer.chanakya_chat_serializer import ChanakyaSearchRequestSerializer
from rest_framework.response import Response
from chanakya.utils import sentry
from chanakya.utils import utility
from chanakya.utils.utility import EncryptionDecryption
from chanakya.utils.mixpanel import _chat_with_chanakya, _create_conversation

logger = logging.getLogger(__name__)


class ChanakyaChatAPis(APIView):

    def get(self, request):
        user_info = request.META.get('user', None)
        auth_user_id = request.META.get("sub", None)
        _create_conversation(auth_user_id)
        if not user_info:
            raise custom_exception.DataNotFound("No User Found")

        conversation = ConversationModel.objects.create(user=user_info)
        cache.set(conversation.id, conversation, timeout=60 * 30)
        # serializer_data = ConversationSerializer(conversation)
        return Response(data={"conversation_id": conversation.id})

    def post(self, request):
        user_info = request.META.get('user', None)
        auth_user_id = request.META.get("sub", None)
        if not user_info:
            raise custom_exception.DataNotFound("No User Found")
        serializer = ChanakyaSearchRequestSerializer(data=request.data)
        if not serializer.is_valid():
            error = next(iter(serializer.errors.values()))[0]
            raise custom_exception.InvalidData(error)
        serialized_data = serializer.validated_data
        conversation_id = serialized_data.get("conversation_id")
        query = serialized_data.get("query")
        conversation_history = None
        utility.check_rate_limit_of_conversation(user_info, rate_limit=40, time_limit=240)
        is_ios = serialized_data.get("is_ios", False)

        prompt_instance = utility.get_prompt_instance(is_ios)
        prompt_builder = PromptBuilder(start_token=prompt_instance.start_token,
                                       end_token=prompt_instance.end_token,
                                       user_token=prompt_instance.user_token,
                                       assistant_token=prompt_instance.assistant_token,
                                       eot_token=prompt_instance.eot_token,
                                       system_message=prompt_instance.system_message,
                                       begin_of_text_token=prompt_instance.begin_of_text_token,
                                       system_token=prompt_instance.system_token
                                       )
        conversation_cache_id = f"conversation_{conversation_id}"
        conversation = cache.get(conversation_cache_id)

        if conversation is None:
            try:
                conversation = ConversationModel.objects.get(id=conversation_id, user=user_info)
                cache.set(conversation_cache_id, conversation)
            except ConversationModel.DoesNotExist:
                raise custom_exception.InvalidData("Provided Conversation is not correct")
            except Exception as e:
                raise custom_exception.InvalidData("Provided Conversation is not correct")
        if conversation is None:
            raise custom_exception.InvalidData("Conversation Not Found")

        # logger.debug(f"Conversation passed to build prompt:\n {conversation}")
        prompt, conversation_history = utility.build_prompt_and_get_conversation_history(conversation, query=query,
                                                                                         prompt_builder=prompt_builder)

        MessageModel.objects.create(conversation=conversation, content=query, role=RoleEnum.USER.value)

        # logger.debug(f"Full prompt:\n {str(prompt)}")
        # logger.info(f"*************************************")

        url = "https://api.together.xyz/v1/chat/completions"
        together_api_token = os.getenv("TOGETHER_API_TOKEN")

        send_request = utility.SendRequestForTogetherStreaming(model="meta-llama/Llama-3-70b-chat-hf", temperature=0.7,
                                                               top_p=0.7, top_k=50, max_tokens=2048,
                                                               repetition_penalty=1.2,
                                                               stop="<|eot_id|>")

        upstream_response = send_request.__call__(together_api_token=together_api_token, prompt=prompt, url=url)
        try:
            def streaming_content_generator():
                text_list = ''
                for chunk in upstream_response.iter_content(chunk_size=8192):
                    yield chunk
                    try:
                        if chunk:
                            json_data = chunk.decode('utf-8').split('\n')
                            for line in json_data:
                                if line.startswith('data: '):
                                    line_data = line[6:].strip()
                                    if line_data:
                                        response = json.loads(line_data)
                                        if 'choices' in response and response['choices']:
                                            text_value = response['choices'][0]['text']
                                            text_list += text_value
                    except Exception as e:
                        logger.debug(f"Error processing chunk: {e}")
                        continue
                # logger.debug(f"Response Text: \n{text_list}")
                # logger.info(f"*************************************")
                _chat_with_chanakya(auth_user_id)
                MessageModel.objects.create(conversation=conversation, content=text_list, role=RoleEnum.ASSISTANT.value)
                # logger.debug(f"Conversation History in ChanakyaChatAPIs.post before title gen: {conversation_history}")
                # logger.debug(f"Conversation History type: {type(conversation_history)}")
                if not conversation_history:
                    logger.info("Triggering Title Generator")
                    messages = MessageModel.objects.filter(conversation=conversation)
                    conversation_history_1 = [{"role": msg.role, "content": msg.content} for msg in messages]
                    generate_conversation_title.delay(conversation.id, conversation_history_1)
                    logger.info("Triggered Celery Task for Title Generation")

            return StreamingHttpResponse(streaming_content_generator(),
                                         content_type=upstream_response.headers.get('Content-Type', 'application/json'),
                                         )
        except Exception as e:
            logger.debug(f"ERROR: {e}")
            sentry.capture_error(message="Error while streaming", user_email=user_info.email, exception=e)
            raise custom_exception.InvalidRequest("Service Unavailable")


class SearchArgumented(APIView):

    def post(self, request):
        user_info = request.META.get('user', None)

        if not user_info:
            raise custom_exception.DataNotFound("No User Found")

        data = request.data

        conversation_id = data.get("conversation_id")

        query = data.get("query")

        if query is None:
            raise custom_exception.DataNotFound("No Query Found")

        conversation = cache.get(conversation_id)

        if conversation is None:
            conversation = ConversationModel.objects.get(id=conversation_id, user=user_info)
            cache.set(conversation.id, conversation)

        if conversation is None:
            raise custom_exception.InvalidData("Conversation Not Found")

        try:

            async def func():
                pass

        except Exception as e:
            sentry.capture_error(message="Error while search argument", user_email=user_info.email, exception=e)
            raise custom_exception.CustomException(detail="Server Error Occured", message="Server Error Occured",
                                                   status_code=500)


class TemporaryChanakyaChatAPis(APIView):
    RATE_LIMIT = int(os.getenv('RATE_LIMIT'))
    RATE_LIMIT_WINDOW = int(os.getenv('RATE_LIMIT_WINDOW'))

    def post(self, request):
        logger.info(f"********** Temporary Chat Begins ***************")
        hash_api_key = request.headers.get('Authorization', None)
        if not hash_api_key:
            return redirect("/400/")
        if not hash_api_key.startswith('Bearer '):
            raise custom_exception.InvalidData("Invalid Key")
        formatted_hash_key = hash_api_key[len('Bearer '):]
        unique_key = self.extract_unique_key(formatted_hash_key)
        logger.debug(f"unique key: {unique_key}")
        if not unique_key:
            return redirect("/403/")

        if self.is_rate_limited(unique_key):
            raise custom_exception.RateLimitExceed("Limit Exceed")
        query = request.data.get("query")

        url = "https://api.together.xyz/v1/chat/completions"
        together_api_token = os.getenv("TOGETHER_API_TOKEN")
        is_ios = request.data.get("is_ios", False)

        prompt_instance = utility.get_prompt_instance(is_ios)
        prompt_builder = PromptBuilder(start_token=prompt_instance.start_token,
                                       end_token=prompt_instance.end_token,
                                       user_token=prompt_instance.user_token,
                                       assistant_token=prompt_instance.assistant_token,
                                       eot_token=prompt_instance.eot_token,
                                       system_message=prompt_instance.system_message,
                                       begin_of_text_token=prompt_instance.begin_of_text_token,
                                       system_token=prompt_instance.system_token
                                       )
        prompt, conversation_history = utility.build_prompt_and_get_conversation_history(conversation=None, query=query,
                                                                                         prompt_builder=prompt_builder)
        send_request = utility.SendRequestForTogetherStreaming(model="meta-llama/Llama-3-70b-chat-hf", temperature=0.7,
                                                               top_p=0.7, top_k=50, max_tokens=2048,
                                                               repetition_penalty=1.2,
                                                               stop="<|eot_id|>")
        upstream_response = send_request.__call__(together_api_token=together_api_token, prompt=prompt,
                                                  url=url)

        try:
            def streaming_content_generator():
                for chunk in upstream_response.iter_content(chunk_size=8192):
                    yield chunk

            self.increment_request_count(unique_key)
            return StreamingHttpResponse(streaming_content_generator(),
                                         content_type=upstream_response.headers.get('Content-Type', 'application/json'),
                                         )
        except Exception as e:
            logger.debug(f"ERROR: {e}")
            sentry.capture_error(message="Error while streaming", user_email="temporary_chat", exception=e)
            raise custom_exception.InvalidRequest("Service Unavailable")

    def is_rate_limited(self, unique_key):
        request_count = cache.get(f"temp_chat_request_count_{unique_key}", 0)
        logger.debug(f"cache rate limit count: {request_count}")
        return request_count >= self.RATE_LIMIT

    def increment_request_count(self, unique_key):
        cache_key = f"temp_chat_request_count_{unique_key}"
        request_count = cache.get(cache_key, 0)
        if request_count == 0:
            cache.set(cache_key, 1, timeout=self.RATE_LIMIT_WINDOW)
        else:
            cache.incr(cache_key)

    def extract_unique_key(self, hash_api_key):
        fernet_key = os.getenv("FERNET_KEY")
        if not fernet_key:
            return None
        try:
            enc_dec = EncryptionDecryption(fernet_key)
            decrypted_api_key = enc_dec.decrypt(hash_api_key)
            temp_chat_api_token, unique_key = decrypted_api_key.split('_', 1)
            temp_chat_decryption_token = os.environ.get("TEMPORARY_CHAT_API_KEYS")
            if temp_chat_api_token == temp_chat_decryption_token:
                return unique_key
        except Exception as e:
            return None
        return None
