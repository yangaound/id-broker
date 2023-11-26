import re
import time

import jwt
from django.conf import settings
from django.http.request import HttpRequest

BUILTIN_USER_POOL = "builtin-user-pool"
EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def generate_verification_code() -> str:
    return str(int(time.time() * 1000000))


def encode_jwt(payload: dict) -> jwt:
    return jwt.encode(payload, key=settings.SECRET_KEY, algorithm="HS512")


def decode_jwt(activate_token: str) -> dict:
    return jwt.decode(activate_token, key=settings.SECRET_KEY, algorithms="HS512")


def build_base_path(request: HttpRequest) -> str:
    return f"{settings.FORCE_SCRIPT_NAME or ''}"
