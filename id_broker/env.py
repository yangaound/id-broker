import os
import re

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get("SECRET_KEY") or "django-insecure-a+lqh%d(^o9srdd8zsn9kqgvw6#mpw08a74vi3ek&jnx-$(!tr"


# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = bool(os.environ.get("DEBUG", ""))


ALLOWED_HOSTS = re.split(r",\s*", _) if (_ := os.environ.get("ALLOWED_HOSTS")) else ["*"]


DATABASES = {
    "default": {
        "ENGINE": os.getenv("DB_ENGINE") or "django.db.backends.postgresql",
        "NAME": os.getenv("DB_NAME") or "identity",
        "USER": os.getenv("DB_USER") or "idadm",
        "PASSWORD": os.getenv("DB_PASSWORD") or "id+123",
        "HOST": os.getenv("DB_HOST") or "127.0.0.1",
        "PORT": os.getenv("DB_PORT") or "5432",
    }
}


STATIC_ROOT = os.environ.get("STATIC_ROOT") or "static/"

# Default primary key field type
# https://docs.djangoproject.com/en/4.1/ref/settings/#default-auto-field


FORCE_SCRIPT_NAME = os.environ.get("FORCE_SCRIPT_NAME")


LOGIN_REDIRECT_URL = os.environ.get(
    "LOGIN_REDIRECT_URL",
    "http://localhost:8000/accounts/profile",
)
LOGOUT_REDIRECT_URL = os.environ.get(
    "LOGOUT_REDIRECT_URL",
    "http://localhost:8000/accounts/login",
)

OAUTH2 = {
    "google": {
        "auth_uri": os.environ.get(
            "GG_AUTH_URI",
            "https://accounts.google.com/o/oauth2/v2/auth",
        ),
        "token_uri": os.environ.get(
            "GG_TOKEN_URI",
            "https://oauth2.googleapis.com/token",
        ),
        "client_id": os.environ.get(
            "GG_CLIENT_ID",
            "199688192618-d0fflt4qitm34of553ecr60fpbfmoirt.apps.googleusercontent.com",
        ),
        "client_secret": os.environ.get("GG_CLIENT_SECRET", "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"),
        "redirect_uri": os.environ.get(
            "GG_REDIRECT_URI",
            "http://localhost:8000/oauth2/google/callback",
        ),
        "scope": re.split(r",\s*", _) if (_ := os.environ.get("GG_SCOPE")) else ["openid", "profile", "email"],
    },
    "azure": {
        "auth_uri": os.environ.get(
            "MS_AUTH_URI",
            "https://login.microsoftonline.com/2fa5e981-5473-46e6-b20d-007ed6aff9d2/oauth2/v2.0/authorize",
        ),
        "token_uri": os.environ.get(
            "MS_TOKEN_URI",
            "https://login.microsoftonline.com/2fa5e981-5473-46e6-b20d-007ed6aff9d2/oauth2/v2.0/token",
        ),
        "client_id": os.environ.get(
            "MS_CLIENT_ID",
            "ee6afbe2-e35e-4195-9d80-dcbc3f5f4a2c",
        ),
        "client_secret": os.environ.get("MS_CLIENT_SECRET", "ozt8Q~rMreB6YSgIAcUwyLCbOKlWLHs0p6Zrdbr9"),
        "redirect_uri": os.environ.get(
            "MS_REDIRECT_URI",
            "http://localhost:8000/oauth2/azure/callback",
        ),
        "scope": re.split(r",\s*", _) if (_ := os.environ.get("MS_SCOPE")) else ["openid", "profile", "email"],
    },
    "line": {
        "auth_uri": os.environ.get(
            "LN_AUTH_URI",
            "https://access.line.me/oauth2/v2.1/authorize",
        ),
        "token_uri": os.environ.get(
            "LN_TOKEN_URI",
            "https://api.line.me/oauth2/v2.1/token",
        ),
        "client_id": os.environ.get(
            "LN_CLIENT_ID",
            "2001887430",
        ),
        "client_secret": os.environ.get(
            "LN_CLIENT_SECRET",
            "b73c39b61bd9b5441451c2738878a097",
        ),
        "redirect_uri": os.environ.get(
            "LN_REDIRECT_URI",
            "http://localhost:8000/oauth2/line/callback",
        ),
        "scope": re.split(r",\s*", _) if (_ := os.environ.get("LN_SCOPE")) else ["openid", "profile", "email"],
    },
}

# CORS
if os.environ.get("CSRF_COOKIE_SAMESITE", "").lower() == "none":
    CSRF_COOKIE_SAMESITE = os.environ["CSRF_COOKIE_SAMESITE"]
    CSRF_COOKIE_SECURE = True
    CSRF_COOKIE_HTTPONLY = False

CORS_ALLOW_CREDENTIALS = bool(os.environ.get("CORS_ALLOW_CREDENTIALS", ""))
CSRF_TRUSTED_ORIGINS = (
    re.split(r",\s*", _) if (_ := os.environ.get("CSRF_TRUSTED_ORIGINS")) else ["http://localhost:8000"]
)
CORS_ORIGIN_WHITELIST = CSRF_TRUSTED_ORIGINS


# Session cookie
SESSION_COOKIE_AGE = int(_) if (_ := os.environ.get("SESSION_COOKIE_AGE")) else 60 * 60
if os.environ.get("SESSION_COOKIE_SAMESITE"):
    SESSION_COOKIE_SAMESITE = os.environ["SESSION_COOKIE_SAMESITE"]
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True


# SMTP
EMAIL_BACKEND = os.environ.get("EMAIL_BACKEND") or "django.core.mail.backends.console.EmailBackend"
EMAIL_HOST = os.environ.get("EMAIL_HOST") or "email-smtp.ap-southeast-1.amazonaws.com"
EMAIL_PORT = int(_) if (_ := os.environ.get("EMAIL_PORT")) else 25
EMAIL_SENDER = os.environ.get("EMAIL_SENDER") or "yin.long@mail.yinlong.link"

ACCOUNT_CONFIRM_EMAIL_SUBJECT = os.environ.get("ACCOUNT_CONFIRM_EMAIL_SUBJECT") or "[ID Broker] - Account confirmation"
# Email Content, the placeholders first_name, activate_token & verification_code must present.
ACCOUNT_CONFIRM_EMAIL_CONTENT = (
    os.environ.get("ACCOUNT_CONFIRM_EMAIL_CONTENT")
    or """"
Dear {first_name},

Thank you for registration our ID Broker! Please click the link below to confirm your account:

http://localhost:8000/accounts/perform-confirmation?activate_token={activate_token}&verification_code={verification_code}&next=/accounts/login

Important Note: This link is valid for 2 days.

Best regards,
Dev Team
"""
)

RESET_PASSWORD_EMAIL_SUBJECT = os.environ.get("RESET_PASSWORD_EMAIL_SUBJECT") or "[ID Broker] - reset password"
# Email Content, the placeholders first_name, reset_token & verification_code must present.
RESET_PASSWORD_EMAIL_CONTENT = (
    os.environ.get("RESET_PASSWORD_EMAIL_CONTENT")
    or """"
Hello {first_name},
Someone, hopefully you, has requested to reset the password for your ID Broker account.
Please click the link below to reset your password:

http://localhost:8000/security/perform-password-reset?reset_token={reset_token}&verification_code={verification_code}

Important Note: This link is valid for 1 days.

Best regards,
Dev Team
"""
)
