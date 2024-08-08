from rest_framework import routers
from django.urls import path, include
from premium_features.views.google_seach_engine import ChanakyaGoogleSearchEngine
from premium_features.views.premium_user import PremiumUserViewSet

router = routers.DefaultRouter()
router.register(r'user', PremiumUserViewSet, basename='premium-user')
router.register(r'google-search', ChanakyaGoogleSearchEngine, basename='google-search')

urlpatterns = [
    path('', include(router.urls)),
]