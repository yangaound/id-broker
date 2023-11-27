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
from django.urls import path, re_path

from . import views

# Wire up our API using automatic URL routing.
# Additionally, we include login URLs for the browsable API.
urlpatterns = [
    path(r"sign-up", views.IDRegister.as_view({"post": "create"})),
    path(r"profile", views.IDProfile.as_view({"get": "retrieve"})),
    path(r"perform-confirmation", views.PerformAccountConfirmationViews.as_view({"get": "retrieve"})),
    path(r"client-password-login", views.ClientPasswordLogin.as_view({"patch": "partial_update"})),
    path(r"update-user-info", views.UpdateUserInfoViews.as_view({"patch": "partial_update"})),
    # Web page
    re_path(r"^federal-signin$", views.render_federal_signin_page),
    re_path(r"^oauth2-signin-error$", views.render_federal_oauth2_signin_error_page),
]
