import json
import logging
import traceback

from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.core.mail import send_mail
from django.db import transaction
from django.http import HttpResponse, JsonResponse, QueryDict
from django.http.request import HttpRequest
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_exempt
from rest_framework import exceptions, mixins, permissions, status, viewsets
from rest_framework.request import Request
from rest_framework.response import Response

from id_broker import helper
from id_broker.account.models import UserDraft, UserProfile
from id_broker.account.serializers import (
    ChangePasswordSerializer,
    CreateIdentitySerializer,
    IdentitySerializer,
    RetrieveIdentitySerializer,
    UpdateUserInfoSerializer,
)


class IDProfile(viewsets.GenericViewSet, mixins.ListModelMixin):
    serializer_class = RetrieveIdentitySerializer
    queryset = User.objects.all()
    permission_classes = (permissions.IsAuthenticated,)

    def list(self, request: Request, *args, **kwargs) -> Response:
        return Response(self.serializer_class(request.user, context=self.get_serializer_context()).data)


class IDRegister(viewsets.GenericViewSet, mixins.CreateModelMixin):
    serializer_class = CreateIdentitySerializer
    queryset = UserDraft.objects.all()

    def create(self, request: Request, *args, **kwargs) -> Response:
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

        verification_code = helper.generate_verification_code()
        activate_token = helper.encode_activate_token(identifier=validated_data["email"])

        user_profile = UserProfile(
            id_provider=helper.BUILTIN_USER_POOL,
            verification_code=verification_code,
            preferred_name="{first_name} {last_name}".format(**validated_data),
        )
        user_draft.user_profile = user_profile

        user_profile.save()
        user_draft.save()

        serializer = self.get_serializer(user_draft)
        headers = self.get_success_headers(serializer.data)

        try:
            self._send_conform_account_email(activate_token, user_draft)
        except Exception:
            logging.error(traceback.format_exc())
            raise

        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    @staticmethod
    def _send_conform_account_email(activate_token: str, user_draft: UserDraft):
        confirm_email_content = settings.ACCOUNT_CONFIRM_EMAIL_CONTENT.format(
            first_name=user_draft.first_name,
            activate_token=activate_token,
            verification_code=user_draft.user_profile.verification_code,
        )
        send_mail(
            settings.ACCOUNT_CONFIRM_EMAIL_SUBJECT,
            confirm_email_content,
            from_email=settings.EMAIL_SENDER,
            recipient_list=[user_draft.email],
            fail_silently=False,
        )


class UpdateUserInfoViews(viewsets.GenericViewSet, mixins.UpdateModelMixin):
    serializer_class = UpdateUserInfoSerializer
    queryset = User.objects.select_related("user_profile").all()
    permission_classes = (permissions.IsAuthenticated,)

    def partial_update(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data

        user: User = request.user
        user.first_name = validated_data.get("first_name") or user.first_name
        user.last_name = validated_data.get("last_name") or user.last_name
        user.save()

        return Response(validated_data)


class ChangePasswordViews(viewsets.GenericViewSet, mixins.UpdateModelMixin):
    serializer_class = ChangePasswordSerializer
    queryset = User.objects.select_related("user_profile").all()
    permission_classes = (permissions.IsAuthenticated,)

    def partial_update(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data

        user: User = request.user

        if not user.check_password(validated_data["password"]):
            return JsonResponse({"message": "Unprocessable Entity."}, status=422)

        user.set_password(validated_data["new_password"])
        user.save()

        # login again as the user's state was changed
        login(request, user)

        return Response(status=200)


@csrf_exempt
@transaction.atomic
def activate_account(request: HttpRequest) -> JsonResponse:
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
        username = helper.decode_activate_token(activate_token)
    except Exception as e:
        logging.warning(str(e))
        return JsonResponse({"message": "Unprocessable Entity."}, status=422)

    qs = UserDraft.objects.select_related("user_profile").filter(
        username=username, user_profile__verification_code=verification_code
    )
    if not qs.exists():
        return JsonResponse({"message": "Invalid link."}, status=422)

    user_draft = qs[0]
    _microseconds = int(helper.generate_verification_code())
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


def csrf_token(request: HttpRequest) -> JsonResponse:
    csrftoken = get_token(request)
    res = JsonResponse({settings.CSRF_COOKIE_NAME: csrftoken})
    res.set_cookie(settings.CSRF_COOKIE_NAME, csrftoken)
    return res


@transaction.atomic
def client_password_login(request: HttpRequest) -> HttpResponse:
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

    login(request, user)
    return HttpResponse()


@csrf_exempt
@transaction.atomic
def activate_password_reset(request: HttpRequest) -> JsonResponse:
    identifier = request.POST.get("email")

    try:
        user = User.objects.get(username=identifier)
    except User.DoesNotExist:
        return JsonResponse({"email": ["Cannot recognize!"]}, status=400)

    verification_code = helper.generate_verification_code()
    reset_passwd_token = helper.encode_activate_token(identifier=identifier)
    user.user_profile.verification_code = verification_code
    user.user_profile.save()

    reset_passwd_email_content = settings.RESET_PASSWORD_EMAIL_CONTENT.format(
        first_name=user.first_name,
        reset_token=reset_passwd_token,
        verification_code=user.user_profile.verification_code,
    )

    try:
        send_mail(
            settings.RESET_PASSWORD_EMAIL_SUBJECT,
            reset_passwd_email_content,
            from_email=settings.EMAIL_SENDER,
            recipient_list=[user.email],
            fail_silently=False,
        )
    except Exception:
        logging.error(traceback.format_exc())
        raise

    return JsonResponse({"message": "Password reset processing is activated now. Please check your email."}, status=200)


@csrf_exempt
@transaction.atomic
def perform_password_reset(request: HttpRequest) -> JsonResponse:
    if request.method not in ("GET", "POST"):
        return JsonResponse({"message": "Method Not Allowed."}, status=405)

    verification_code = request.GET.get("verification_code", "") or request.POST.get("verification_code", "")
    reset_token = request.GET.get("reset_token", "") or request.POST.get("reset_token", "")
    new_password = request.GET.get("new_password", "") or request.POST.get("new_password", "")

    if not (verification_code and reset_token and new_password):
        return JsonResponse({"message": "Unprocessable Entity."}, status=422)

    try:
        identifier = helper.decode_activate_token(reset_token)
    except Exception as e:
        logging.warning(str(e))
        return JsonResponse({"message": "Unprocessable Entity."}, status=422)

    qs = User.objects.select_related("user_profile").filter(
        username=identifier, user_profile__verification_code=verification_code
    )
    if not qs.exists():
        return JsonResponse({"message": "Invalid link."}, status=422)

    user: User = qs[0]
    _microseconds = int(helper.generate_verification_code())
    if 60 * 60 * 25 * 1 * 1000000 < _microseconds - int(verification_code):
        return JsonResponse({"message": "Expired link."}, status=422)

    user.set_password(new_password)
    user.save()

    return JsonResponse({"message": f"Your password has been reset."}, status=200)
