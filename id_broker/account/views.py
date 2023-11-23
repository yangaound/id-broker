import json
import logging
import time
import traceback

import jwt
from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.core.mail import send_mail
from django.db import transaction
from django.http import HttpResponse, JsonResponse, QueryDict
from django.http.request import HttpRequest
from django.middleware.csrf import get_token
from rest_framework import exceptions, mixins, permissions, status, viewsets
from rest_framework.response import Response

from id_broker.account.models import UserDraft, UserProfile
from id_broker.account.serializers import CreateIdentitySerializer, IdentitySerializer, RetrieveIdentitySerializer


class IDProfile(viewsets.GenericViewSet, mixins.ListModelMixin):
    serializer_class = RetrieveIdentitySerializer
    queryset = User.objects.all()
    permission_classes = (permissions.IsAuthenticated,)

    def list(self, request, *args, **kwargs):
        return Response(self.serializer_class(request.user, context=self.get_serializer_context()).data)


class IDRegister(viewsets.GenericViewSet, mixins.CreateModelMixin):
    serializer_class = CreateIdentitySerializer
    queryset = UserDraft.objects.all()

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        validated_data = serializer.validated_data
        if (
            User.objects.filter(email=validated_data["email"]).exists()
            or UserDraft.objects.filter(email=validated_data["email"]).exists()
        ):
            raise exceptions.ValidationError(
                {"email": ["This email was registered; please use forgot password to reset it."]}
            )

        user_draft = UserDraft(**validated_data)
        user_draft.username = validated_data["email"]
        user_draft.set_password(validated_data["password"])

        verification_code = IDRegister.generate_verification_code()
        activate_token = IDRegister.encode_activate_token(username=validated_data["email"])

        user_profile = UserProfile(
            verification_code=verification_code,
            preferred_name="{first_name} {last_name}".format(**validated_data),
        )
        user_draft.user_profile = user_profile

        user_profile.save()
        user_draft.save()

        serializer = self.get_serializer(user_draft)
        headers = self.get_success_headers(serializer.data)

        try:
            absolute_uri = request.build_absolute_uri(None)
            self._send_conform_account_email(absolute_uri, activate_token, user_draft)
        except Exception:
            logging.error(traceback.format_exc())
            return JsonResponse(
                data={"message": f"Can not send email to {user_draft.email}."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    @staticmethod
    def generate_verification_code() -> str:
        return str(int(time.time() * 1000000))

    @staticmethod
    def encode_activate_token(username: str) -> str:
        return jwt.encode({"sub": username}, key=settings.SECRET_KEY, algorithm="HS256")

    @staticmethod
    def decode_activate_token(activate_token: str) -> str:
        return jwt.decode(activate_token, key=settings.SECRET_KEY, algorithms="HS256")["sub"]

    @staticmethod
    def _send_conform_account_email(activate_token: str, user_draft: UserDraft):
        confirm_email_content = settings.ACCOUNT_CONFIRM_EMAIL_CONTENT.format(
            first_name=user_draft.first_name,
            activate_token=activate_token,
            verification_code=user_draft.user_profile.verification_code,
        )
        send_mail(
            settings.EMAIL_SUBJECT,
            confirm_email_content,
            from_email=settings.EMAIL_SENDER,
            recipient_list=[user_draft.email],
            fail_silently=False,
        )


@transaction.atomic
def activate_account(request: HttpRequest):
    if request.method == "GET":
        verification_code = request.GET.get("verification_code", "")
        activate_token = request.GET.get("activate_token", "")
    elif request.method == "POST":
        verification_code = request.POST.get("verification_code", "")
        activate_token = request.POST.get("activate_token", "")
    else:
        return JsonResponse({"message": "Method Not Allowed."}, status=405)

    if not (verification_code and activate_token):
        return JsonResponse({"message": "Unprocessable Entity."}, status=422)

    try:
        username = IDRegister.decode_activate_token(activate_token)
    except Exception as e:
        logging.warning(str(e))
        return JsonResponse({"message": "Unprocessable Entity."}, status=422)

    qs = UserDraft.objects.select_related("user_profile").filter(
        username=username, user_profile__verification_code=verification_code
    )
    if not qs.exists():
        return JsonResponse({"message": "Invalid link."}, status=422)

    user_draft = qs[0]
    _microseconds = int(IDRegister.generate_verification_code())
    if 60 * 60 * 25 * 2 * 1000000 < _microseconds - int(user_draft.user_profile.verification_code):
        return JsonResponse({"message": "Expired link."}, status=422)

    qs = User.objects.filter(username=username)
    if not qs.exists():
        user = User(
            username=username,
            password=user_draft.password,
            first_name=user_draft.first_name,
            last_name=user_draft.last_name,
            email=user_draft.email,
            is_active=True,
        )
        profile = user_draft.user_profile
        profile.user = user
        user.save()
        profile.save()

        return JsonResponse({"message": f"Your account {username} is activated now."}, status=201)

    return JsonResponse({"message": f"Your account has been activated."}, status=200)


# Create your views here.
def csrf_token(request):
    csrftoken = get_token(request)
    res = JsonResponse({settings.CSRF_COOKIE_NAME: csrftoken})
    res.set_cookie(settings.CSRF_COOKIE_NAME, csrftoken)
    return res


@transaction.atomic
def password_login(request: HttpRequest):
    try:
        if request.content_type == "application/json":
            serializer = IdentitySerializer(data=json.load(request))
        else:
            serializer = IdentitySerializer(data=QueryDict(request.POST.urlencode()))
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data
    except Exception as e:
        logging.warning(str(e))
        raise PermissionDenied

    qs = User.objects.filter(username=validated_data["email"])
    if not qs.exists():
        logging.warning("The email '{email}' does not exist.".format(**validated_data))
        raise PermissionDenied

    user = qs.first()
    if not user.check_password(validated_data["password"]):
        logging.warning("Incorrect password entered for user '{email}'.".format(**validated_data))
        raise PermissionDenied

    login(
        request,
        user,
        backend="django.contrib.auth.backends.ModelBackend",
    )
    return HttpResponse()
