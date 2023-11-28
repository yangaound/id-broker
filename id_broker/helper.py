import logging
from datetime import datetime, timedelta
from typing import Optional, Union
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from django.conf import settings
from django.contrib.auth.models import User
from django.http.request import HttpRequest
from django.utils.http import base36_to_int, int_to_base36
from jose import ExpiredSignatureError, JWTError, jwt
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request

BUILTIN_USER_POOL = "builtin-user-pool"

_INIT_PK_NUMBER = 1 << 25
MAX_PK_NUMBER = 1 << 63


def pk_to_base36(num: int) -> str:
    num += _INIT_PK_NUMBER
    return int_to_base36(num)


def base36_to_pk(chars: str) -> int:
    num = base36_to_int(chars)
    num -= _INIT_PK_NUMBER
    return num


def generate_id_token(user: User) -> str:
    utcnow = datetime.utcnow()

    id_token_payload = {
        "sub": str(user.pk),
        "id_provider_name": user.user_profile.id_provider,
        "iat": utcnow,
        "exp": utcnow + timedelta(seconds=settings.ID_TOKEN_VALIDITY),
    }

    return _encode_jwt(id_token_payload)


def _encode_jwt(payload: dict) -> jwt:
    return jwt.encode(payload, key=settings.SECRET_KEY, algorithm="HS512")


def _decode_jwt(activate_token: str) -> dict:
    payload = jwt.decode(
        activate_token,
        settings.SECRET_KEY,
        algorithms=["HS512"],
        options={"verify_aud": False, "verify_signature": True},
    )
    return payload


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

        try:
            id_token_payload = _decode_jwt(token)
        except ExpiredSignatureError:
            raise AuthenticationFailed("Token has expired.")
        except JWTError as e:
            logging.error(f"Decode JWT `{token}` error with message `{e}`")
            raise AuthenticationFailed("Token has expired or corrupted")

        user = User.objects.select_related("user_profile").get(pk=id_token_payload["sub"])

        return user, None

    def authenticate_header(self, request):
        return self.TOKEN_NAME
