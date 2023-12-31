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
from django.urls import path
from django.views.decorators.csrf import csrf_exempt

from . import views

# Wire up our API using automatic URL routing.
# Additionally, we include login URLs for the browsable API.
urlpatterns = [
    path(r"csrf-token", views.RetrieveCsrfTokenViews.as_view({"get": "retrieve"})),
    path(r"id-token", csrf_exempt(views.RequestIDTokenViews.as_view({"post": "create"}))),
    path(r"change-password", views.ChangePasswordViews.as_view({"patch": "partial_update"})),
    path(
        r"activate-password-reset", csrf_exempt(views.ActivatePasswordResetViews.as_view({"patch": "partial_update"}))
    ),
    path(r"perform-password-reset", csrf_exempt(views.PerformPasswordResetViews.as_view({"patch": "partial_update"}))),
]
