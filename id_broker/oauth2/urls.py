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
from django.conf import settings
from django.urls import re_path

from . import views

supported_id_providers = r"^(?P<id_provider>(%s))" % "|".join(settings.OAUTH2.keys())

urlpatterns = [
    re_path(f"{supported_id_providers}/auth$", views.oauth2_auth_rdr),
    re_path(f"{supported_id_providers}/callback$", views.oauth2_callback),
]
