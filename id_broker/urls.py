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
import os

from django.contrib import admin
from django.urls import include, path
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions

# Wire up our API using automatic URL routing.
# Additionally, we include login URLs for the browsable API.

schema_view = get_schema_view(
    openapi.Info(
        title="ID Broker",
        default_version="v1",
        description="""Identity and group management service. It also supports SSO through 
                       OAuth2 idP (Google, Microsoft, Line).""",
        contact=openapi.Contact(email="fofx@outlook.com"),
        license=openapi.License(name="MIT License"),
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
    url=os.environ.get("BASE_URL"),
)


urlpatterns = [
    path(r"oauth2/", include("id_broker.oauth2.urls")),
    path(r"security/", include("id_broker.security.urls")),
    path(r"accounts/", include("id_broker.account.urls")),
    path(r"accounts/", include("rest_framework.urls", namespace="account")),
    path(r"admin/", admin.site.urls),
    path(r"", schema_view.with_ui("swagger", cache_timeout=0), name="schema-swagger-ui"),
]
