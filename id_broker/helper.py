import datetime
import re
import time
from typing import Union
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import jwt
from django.conf import settings
from django.contrib.auth.models import User
from django.http.request import HttpRequest
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
