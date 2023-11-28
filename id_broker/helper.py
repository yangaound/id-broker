import datetime
import re
import time
from typing import Optional, Union
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import jwt
from django.conf import settings
from django.contrib.auth.models import User
from django.http.request import HttpRequest
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request

BUILTIN_USER_POOL = "builtin-user-pool"
EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def generate_verification_code() -> str:
    return str(int(time.time() * 1000000))


def generate_id_token(user: User) -> str:
    utcnow = datetime.datetime.utcnow()

    id_token_payload = {
        "sub": user.pk,
        "id_provider_name": user.user_profile.id_provider,
        "iat": utcnow,
        "exp": utcnow + datetime.timedelta(seconds=60 * 60 * 4),
    }

    return encode_jwt(id_token_payload)


def encode_jwt(payload: dict) -> jwt:
    return jwt.encode(payload, key=settings.SECRET_KEY, algorithm="HS512")


def decode_jwt(activate_token: str) -> dict:
    return jwt.decode(activate_token, key=settings.SECRET_KEY, algorithms="HS512")


def build_base_path(_: Union[HttpRequest, Request]) -> str:
    return f"{settings.FORCE_SCRIPT_NAME or ''}"


def add_query_params_into_url(original_url, new_params):
    url_parts = urlparse(original_url)
    # Extract existing query parameters
    existing_params = parse_qs(url_parts.query)
    # Append new parameters
    existing_params.update(new_params)

    updated_query = urlencode(existing_params, doseq=True)
    updated_url_parts = url_parts._replace(query=updated_query)
    updated_url = urlunparse(updated_url_parts)

    return updated_url


def extract_bearer_token_from_header(request: Request) -> Optional[str]:
    """
    Extracts the Bearer JWT token from the DRF request object.
    Returns None if the token is not present or invalid.
    """
    authorization_header = request.headers.get("Authorization")

    if not authorization_header or not authorization_header.startswith("Bearer "):
        return None

    token = authorization_header.split("Bearer ")[1].strip()

    return token


class IdTokenAuthentication(BaseAuthentication):
    TOKEN_NAME = "id_token"

    def authenticate(self, request: Request):
        token = extract_bearer_token_from_header(request) or request.query_params.get(self.TOKEN_NAME) or ""

        if not token:
            return

        id_token_payload = decode_jwt(token)
        if id_token_payload["exp"] < datetime.datetime.utcnow().timestamp():
            raise AuthenticationFailed("Token has expired")

        try:
            user = User.objects.get(pk=id_token_payload["sub"])
        except User.DoesNotExist:
            raise AuthenticationFailed("User does not exist")

        return user, None

    def authenticate_header(self, request):
        return self.TOKEN_NAME
