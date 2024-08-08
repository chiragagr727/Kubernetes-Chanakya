import json
from langchain_google_community import GoogleSearchAPIWrapper
from langchain_core.tools import Tool
from langgraph.graph import END, StateGraph
from typing_extensions import TypedDict
import os
from premium_features.views import gs_prompt
from langchain_core.output_parsers import JsonOutputParser, StrOutputParser
from rest_framework import viewsets
from django.http import StreamingHttpResponse, JsonResponse
from chanakya.utils import custom_exception
import logging
from langchain_together import ChatTogether
from chanakya.models.conversation import ConversationModel, MessageModel
from chanakya.enums.role_enum import RoleEnum
from chanakya.utils import mixpanel
from chanakya.serializer.chanakya_chat_serializer import ChanakyaSearchRequestSerializer
from chanakya.utils.prompt_builder import PromptBuilder, GoogleSearchPromptBuilder
from chanakya.utils.utility import get_prompt_instance, build_prompt_and_get_conversation_history
from chanakya.tasks.title_generator_task import generate_conversation_title

logger = logging.getLogger(__name__)


class GraphState(TypedDict):
    question: str
    generation: str
    search_query: str
    context: str


class ChanakyaGoogleSearchEngine(viewsets.ViewSet):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.chat = ChatTogether(
            model="meta-llama/Llama-3-70b-chat-hf",
            together_api_key=os.environ.get("TOGETHER_API_TOKEN")
        )

        self.search = GoogleSearchAPIWrapper()
        self.search_tool = Tool(
            name="google_search",
            description="Search Google for recent results.",
            func=self.top5_results,
        )

        self.search_based_prompt = gs_prompt.search_based_prompt
        self.normal_prompt = gs_prompt.normal_prompt
        self.search_based_chain = self.search_based_prompt | self.chat | StrOutputParser()
        self.normal_chain = self.normal_prompt | self.chat | StrOutputParser()

        self.prompt_instance = GoogleSearchPromptBuilder()
        self.router_prompt = self.prompt_instance.build_prompt_for_router(model_name="chanakya-v1-router")
        self.query_prompt = self.prompt_instance.build_prompt_for_query_prompt(mode_name="chanakya-v1-query")
        self.question_router = self.router_prompt | self.chat | JsonOutputParser()
        self.query_chain = self.query_prompt | self.chat | JsonOutputParser()

    def create(self, request):
        user_info = request.META.get('user', None)
        auth_user_id = request.META.get("sub", None)
        if not user_info:
            raise custom_exception.DataNotFound("User not found")
        serializer = ChanakyaSearchRequestSerializer(data=request.data)
        if not serializer.is_valid():
            error = next(iter(serializer.errors.values()))[0]
            raise custom_exception.InvalidData(error)
        serialized_data = serializer.validated_data
        question = serialized_data.get('query')
        conversation = serialized_data.get('conversation_id', None)
        logger.info(f"************** Chanakya web search route***********************")
        try:
            conversation = ConversationModel.objects.get(id=conversation, user=user_info)
        except ConversationModel.DoesNotExist:
            raise custom_exception.InvalidData("Conversation does not exist")
        except Exception as e:
            raise custom_exception.InvalidData("Provided Conversation is not correct")
        if not conversation:
            raise custom_exception.DataNotFound("Conversation not found")
        if question is None:
            raise custom_exception.DataNotFound("Query parameter is required")

        prompt_instance = get_prompt_instance()
        prompt_builder = PromptBuilder(start_token=prompt_instance.start_token,
                                       end_token=prompt_instance.end_token,
                                       user_token=prompt_instance.user_token,
                                       assistant_token=prompt_instance.assistant_token,
                                       eot_token=prompt_instance.eot_token,
                                       system_message=prompt_instance.system_message,
                                       begin_of_text_token=prompt_instance.begin_of_text_token,
                                       system_token=prompt_instance.system_token
                                       )
        prompt, conversation_history = build_prompt_and_get_conversation_history(conversation, query=question,
                                                                                 prompt_builder=prompt_builder)
        logger.debug(f"prompt history of chanakya search:\n {prompt}")
        logger.debug(f"conversation history of chanakya search:\n {conversation_history}")
        MessageModel.objects.create(conversation=conversation, content=question, role=RoleEnum.USER.value)
        request_id = getattr(request, 'request_id', None)
        unique_id = f'{request_id}-chanakya'
        try:
            def response_generator():
                try:
                    yield f"data: {json.dumps({'id': unique_id, 'status': 'Processing'})}\n\n"

                    workflow = StateGraph(GraphState)
                    workflow.add_node("websearch", self.web_search)
                    workflow.add_node("transform_query", self.transform_query)
                    # workflow.add_node("generate_with_search", self.generate_with_search)
                    # workflow.add_node("generate_without_search", self.generate_without_search)

                    workflow.set_conditional_entry_point(
                        self.route_question,
                        {
                            "websearch": "transform_query",
                            "generate_without_search": "generate_without_search",
                        },
                    )

                    workflow.add_edge("transform_query", "websearch")
                    workflow.add_edge("websearch", "generate_with_search")
                    workflow.add_edge("generate_with_search", END)
                    workflow.add_edge("generate_without_search", END)

                    route_step = self.route_question({"question": question})
                    complete_text = ""
                    logger.debug(f"route step: {route_step}")
                    # for websearch route
                    if route_step == "websearch":
                        yield f"data: {json.dumps({'id': unique_id, 'step': True})}\n\n"
                        context = self.search_tool.run(question)
                        # for link generate
                        links = [result['link'] for result in context]
                        generation_with_links = ""
                        for idx, link in enumerate(links, start=1):
                            generation_with_links += f"{idx}. [{link}]({link})\n"
                        sources = {'id': unique_id, 'sources': generation_with_links}
                        yield f"data: {json.dumps(sources)}\n\n"

                        # for context generation
                        for gen in self.search_based_chain.invoke({"context": context, "question": prompt}):
                            complete_text += gen
                            response_data = {'id': unique_id, "response": gen}
                            logger.debug(f"response: {response_data}")
                            yield f"data: {json.dumps(response_data)}\n\n"
                        mixpanel._chat_with_google_search(auth_user_id)
                    #  for without web search route
                    elif route_step == "generate_without_search":
                        yield f"data: {json.dumps({'id': unique_id, 'step': False})}\n\n"

                        # for context gen
                        for gen in self.normal_chain.invoke({"question": prompt}):
                            complete_text += gen
                            response_data = {'id': unique_id, "response": gen}
                            logger.debug(f"response: {response_data}")
                            yield f"data: {json.dumps(response_data)}\n\n"
                        mixpanel._chat_without_web_search(auth_user_id)
                    else:
                        yield f"data: {json.dumps({'id': unique_id, 'step': None})}\n\n"
                    MessageModel.objects.create(conversation=conversation, content=complete_text,
                                                role=RoleEnum.ASSISTANT.value)
                    if not conversation_history:
                        messages = MessageModel.objects.filter(conversation=conversation)
                        conversation_history_1 = [{"role": msg.role, "content": msg.content} for msg in messages]
                        generate_conversation_title.delay(conversation.id, conversation_history_1)
                    # local_agent = workflow.compile()
                    # output = local_agent.invoke({"question": question})
                    yield f"data: {json.dumps({'id': unique_id, 'status': 'End'})}\n\n"
                except Exception as e:
                    yield f"data: {json.dumps({'error': str(e)})}\n\n"

            response = StreamingHttpResponse(response_generator())
            response['Cache-Control'] = 'no-cache'
            response['Content-Type'] = 'text/event-stream'
            response['X-Accel-Buffering'] = 'no'

            return response

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)

    # def generate_with_search(self, state):
    #     print("generating with search")
    #     question = state["question"]
    #     context = state["context"]
    #     generation = self.search_based_chain.invoke({"context": context, "question": question})
    #     return {"generation": generation}
    #
    # def generate_without_search(self, state):
    #     print("Step: Generating Response without Web Search Context")
    #     question = state["question"]
    #     generation = self.normal_chain.invoke({"question": question})
    #     return {"generation": generation}

    def route_question(self, state):
        logger.info("Step: Routing Query")
        question = state['question']
        output = self.question_router.invoke({"question": question})
        if output['choice'] == "web_search":
            logger.info("Step: Routing Query to Web Search")
            return "websearch"
        elif output['choice'] == 'generate':
            logger.info("Step: Routing Query to Generation without Web Search")
            return "generate_without_search"

    def transform_query(self, state):
        logger.info("Step: Optimizing Query for Web Search")
        question = state['question']
        gen_query = self.query_chain.invoke({"question": question})
        search_query = gen_query["query"]
        return {"search_query": search_query}

    def web_search(self, state):
        search_query = state['search_query']
        logger.info(f'Step: Searching the Web for: "{search_query}"')
        search_result = self.search_tool.run(search_query)
        return {"context": search_result}

    def top5_results(self, query):
        return self.search.results(query, 5)
