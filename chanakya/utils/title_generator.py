import os
import logging
from chanakya.utils.llmcall import call_llm
from chanakya.utils import sentry

logger = logging.getLogger(__name__)


class ConversationTitleGenerator:
    sys_prompt = "<|begin_of_text|> <|start_header_id|>system<|end_header_id|> You are an conversation title generator. Your job is to make apt title in 4-5 words using the conversation user provides. Keep it relatable to conversation and only give title not anything else. <|eot_id|>"

    def generate_title(self, conversation):
        user_query = ''
        assistant_answer = ''
        for con in conversation:
            if con["role"] == "user":
                user_query = con["content"]
            elif con["role"] == "assistant":
                assistant_answer = con["content"]
            else:
                logger.error(f"Got Invalid role {con['role']} and the full obj: {con}")
        prompt = self.sys_prompt + "<|start_header_id|>user<|end_header_id|>" + user_query + "<|eot_id_|> <|start_header_id|>assistant<|end_header_id|>" + assistant_answer + "<|eot_id_|> <|start_header_id|>assistant<|end_header_id|>"
        logger.debug(f"In Conversation Title Generator Prompt: {prompt}")
        try:
            result = call_llm(prompt=prompt, max_tokens=15)
            logger.debug(f"After LLM call result: {result}")
            result = result["choices"][0]["message"]["content"]
            logger.debug(f"After LLM call result content: {result}")
            return result.strip()
        except Exception as e:
            sentry.capture_exception(message=f"Error while title generator", exception=e)
            logger.error(f"Error Occured: {e}")

        return "New Chat"
