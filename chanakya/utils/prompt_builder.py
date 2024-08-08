from django.core.cache import cache
from django.utils.encoding import force_bytes
from chanakya.utils import utility
from langchain.prompts import PromptTemplate
import logging

logger = logging.getLogger(__name__)


class PromptBuilder:
    def __init__(self, start_token="", end_token="", user_token="", assistant_token="", eot_token="", system_message="",
                 begin_of_text_token="", system_token=""):
        self.start_token = start_token
        self.end_token = end_token
        self.user_token = user_token
        self.assistant_token = assistant_token
        self.eot_token = eot_token
        self.system_message = system_message
        self.begin_of_text_token = begin_of_text_token
        self.system_token = system_token

        self.static_prompt = f"{self.begin_of_text_token}{self.system_token}\n{self.system_message}{self.eot_token}\n"

    def build_prompt(self, conversation_history=None, user_question=""):
        # Cache prompts
        cache_key = force_bytes(
            'prompt_builder_' + '_'.join([str(m['content']) for m in conversation_history]) + user_question)
        cached_prompt = cache.get(cache_key)
        if cached_prompt:
            return cached_prompt

        if conversation_history is None:
            conversation_history = []
        elif not isinstance(conversation_history, list):
            raise ValueError("conversation_history must be a list of dictionaries")

        if not isinstance(user_question, str):
            raise ValueError("user_question must be a string")

        formatted_history = "\n".join(
            f"{getattr(self, message['role'] + '_token', '')}\n{message['content']}{self.eot_token}"
            for message in conversation_history
        )
        logger.debug(f"in utils.prompt_builder formatted_hisory:\n{formatted_history}")
        logger.info(f"*************************************")
        new_prompt = self.static_prompt
        if formatted_history:
            new_prompt += formatted_history + "\n"
        new_prompt += f"{self.user_token}\n{user_question}{self.eot_token}\n{self.assistant_token}\n"

        cache.set(cache_key, new_prompt, timeout=3600)
        logger.debug(f"in utils.prompt_builder new_prompt:\n{new_prompt}")
        logger.info(f"*************************************")
        return new_prompt


class GoogleSearchPromptBuilder:

    def build_prompt_for_router(self, model_name):
        instance = utility.get_prompt_instance_for_gs(model_name)
        assistant_token = instance.assistant_token
        eot_token = instance.eot_token
        system_message = instance.system_message
        begin_of_text_token = instance.begin_of_text_token
        system_token = instance.system_token
        router_prompt = PromptTemplate(
            template=f'''\n
            {begin_of_text_token}\n
            {system_token}\n
            {system_message}\n
            Question to route: {{question}}\n
            {eot_token}\n
            {assistant_token}\n
            ''',
            input_variables=["question"],
        )

        return router_prompt

    def build_prompt_for_query_prompt(self, mode_name):
        instance = utility.get_prompt_instance_for_gs(mode_name)
        assistant_token = instance.assistant_token
        eot_token = instance.eot_token
        system_message = instance.system_message
        begin_of_text_token = instance.begin_of_text_token
        system_token = instance.system_token
        router_prompt = PromptTemplate(
            template=f'''\n
                   {begin_of_text_token}\n
                   {system_token}\n
                   {system_message}\n
                   Question to route: {{question}}\n
                   {eot_token}\n
                   {assistant_token}\n
                   ''',
            input_variables=["question"],
        )

        return router_prompt
