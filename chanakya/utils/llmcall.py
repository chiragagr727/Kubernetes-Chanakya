import os
import logging
import requests
import json
from chanakya.utils import sentry

logger = logging.getLogger(__name__)


def call_llm(prompt, model="meta-llama/Llama-3-70b-chat-hf", max_tokens=100, stop_seq="<|eot_id|>"):
    url = "https://api.together.xyz/v1/chat/completions"

    payload = {
        "model": model,
        "prompt": str(prompt),
        "temperature": 0.7,
        "top_p": 0.7,
        "top_k": 50,
        "max_tokens": max_tokens,
        "repetition_penalty": 1.2,
        "type": "chat",
        "stop": stop_seq,
    }

    headers = {
        "Authorization": f"Bearer {os.getenv('TOGETHER_API_TOKEN')}",
        "Accept": "*/*",
        "Content-Type": "application/json"
    }
    # logger.debug(f"Payload: {json.dumps(payload)}")
    # response = requests.post(url=url,data=json.dumps(payload),headers=headers)

    # logger.debug(f"Full response: {response.raw}")

    # if response.status_code == 200:
    #     try:
    #         return response.json()
    #     except ValueError as e:
    #         logger.error(f"Error parsing JSON response: {e}")
    #         return None
    # else:
    #     logger.debug(f"Request to {url} with payload: {json.dumps(payload)}")
    #     logger.error(f"Call LLM failed with status code {response.status_code}: {response.content}")

    # return None
    logger.debug(f"Payload: {json.dumps(payload)}")

    response = requests.post(url=url, data=json.dumps(payload), headers=headers)
    logger.debug(f"Full response: {response.content}")

    if response.status_code == 200:
        try:
            return response.json()
        except ValueError as e:
            sentry.capture_exception(message=f"Error call llm of model: {model}", exception=e)
            logger.error(f"Error parsing JSON response: {e}")
            return None
    else:
        logger.debug(f"Request to {url} with payload: {json.dumps(payload)}")
        sentry.capture_exception(message=f"Request to {url} with payload: {json.dumps(payload)}", exception=None)
        logger.error(f"Call LLM failed with status code {response.status_code}: {response.content}")

    return None
