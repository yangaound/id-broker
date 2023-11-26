"""id_broker URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
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
from django.contrib import admin
from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .account import views

# Wire up our API using automatic URL routing.
# Additionally, we include login URLs for the browsable API.

router = DefaultRouter()

router.register(r"account/sign-up", views.IDRegister, basename="sign-up-account")
router.register(r"account/profile", views.IDProfile, basename="user-profile")

urlpatterns = [
    path(r"", include(router.urls)),
    path(r"oauth2/", include("id_broker.oauth2.urls")),
    path(r"security/", include("id_broker.security.urls")),
    path(r"account/", include("id_broker.account.urls")),
    path(r"account/", include("rest_framework.urls", namespace="account")),
    path(r"admin/", admin.site.urls),
]
