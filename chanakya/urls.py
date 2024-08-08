from django.urls import path, include
from chanakya.views.conversation_views import ConversationViewSet, ChanakyaChatFeedback
from chanakya.views.chanakya_chat import ChanakyaChatAPis, TemporaryChanakyaChatAPis
from chanakya.views.user_view import UserViewSet
from rest_framework import routers
from chanakya.views.suggestion import SuggestionViewSet
from chanakya.views.text_to_speech import TextToSpeechApiView

router = routers.DefaultRouter()
router.register(r'auth', UserViewSet, basename='auth')
router.register(r'history', ConversationViewSet, basename='conversation')
router.register(r'suggestions', SuggestionViewSet, basename='suggestions')
router.register(r'feedback', ChanakyaChatFeedback, basename='feedback')
router.register(r'text-to-speech', TextToSpeechApiView, basename='text-to-speech')

urlpatterns = [
    path('', include(router.urls)),
    path('chat/', ChanakyaChatAPis.as_view()),
    path('temporary/chat/', TemporaryChanakyaChatAPis.as_view()),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework'))
]
