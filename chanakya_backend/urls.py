"""
URL configuration for chanakya_backend project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.contrib import admin
from django.urls import include
from django.urls import path
from django.views import defaults as default_views
from django.conf.urls.static import static
from premium_features.views.subscription_webhook import SubScriptionWebhook
from chanakya.admin import admin_site

urlpatterns = [
    path(settings.ADMIN_URL, admin_site.urls),
    path('chanakya/', include("chanakya.urls")),
    path('chanakya-premium/', include('premium_features.urls')),
    path('subscription/webhook/', SubScriptionWebhook.as_view()),
]

# urlpatterns += admin_urlpatterns
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

# silk
urlpatterns += [path('chanakya/debugger/', include('silk.urls', namespace='silk'))]

# Swagger file

# error pages
urlpatterns += [
    path("400/", default_views.bad_request, kwargs={"exception": Exception("Bad Request!")}),
    path("403/", default_views.permission_denied, kwargs={"exception": Exception("Permission Denied")}),
    path("404/", default_views.page_not_found, kwargs={"exception": Exception("Page not Found")}),
    path("500/", default_views.server_error),
]
