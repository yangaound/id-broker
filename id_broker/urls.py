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
from django.urls import include, path, re_path
from rest_framework import routers

from id_broker.account import views as account_views
from id_broker.oauth2 import views as oauth2_views

router = routers.DefaultRouter()

router.register(r"sign-up", account_views.IDRegister, basename="sign-up-account")
router.register(r"profile", account_views.IDProfile, basename="user-profile")


# Wire up our API using automatic URL routing.
# Additionally, we include login URLs for the browsable API.
urlpatterns = [
    re_path(
        r"^oauth2/(?P<id_provider>\w+)/auth$",
        oauth2_views.oauth2_auth_rdr,
    ),
    re_path(
        r"^oauth2/(?P<id_provider>\w+)/callback$",
        oauth2_views.oauth2_callback,
    ),
    path(r"account/perform-confirmation/", account_views.activate_account),
    path(r"account/csrf-token/", account_views.csrf_token),
    path(r"account/client-password-login/", account_views.client_password_login),
    path(r"account/update-user-info/", account_views.UpdateUserInfoViews.as_view({"patch": "partial_update"})),
    path(r"account/change-password/", account_views.ChangePasswordViews.as_view({"patch": "partial_update"})),
    path(r"account/active-password-reset/", account_views.activate_password_reset),
    path(r"account/perform-password-reset/", account_views.perform_password_reset),
    path(r"account/", include("rest_framework.urls", namespace="account")),
    path(r"account/", include(router.urls)),
    path(r"admin/", admin.site.urls),
    path(r"federal-web/", include("id_broker.federal_page.urls")),
]
