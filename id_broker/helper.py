import re
import time

import jwt
from django.conf import settings

BUILTIN_USER_POOL = "builtin-user-pool"
EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def generate_verification_code() -> str:
    return str(int(time.time() * 1000000))


def encode_activate_token(identifier: str) -> str:
    return jwt.encode({"sub": identifier}, key=settings.SECRET_KEY, algorithm="HS256")


def decode_activate_token(activate_token: str) -> str:
    return jwt.decode(activate_token, key=settings.SECRET_KEY, algorithms="HS256")["sub"]
