import json
import logging
import traceback

from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.core.mail import send_mail
from django.db import transaction
from django.http import HttpRequest, JsonResponse, QueryDict
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_exempt
from rest_framework import mixins, permissions, viewsets
from rest_framework.response import Response

from id_broker import helper
from id_broker.account.serializers import IdentitySerializer

from .serializers import ChangePasswordSerializer


def csrf_token(request: HttpRequest) -> JsonResponse:
    csrftoken = get_token(request)
    res = JsonResponse({settings.CSRF_COOKIE_NAME: csrftoken})
    res.set_cookie(settings.CSRF_COOKIE_NAME, csrftoken)
    return res


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
def activate_password_reset(request: HttpRequest) -> JsonResponse:
    identifier = request.POST.get("email")

    try:
        user = User.objects.get(username=identifier)
    except User.DoesNotExist:
        return JsonResponse({"email": ["Cannot recognize!"]}, status=400)

    verification_code = helper.generate_verification_code()
    reset_passwd_token = helper.encode_jwt({"sub": identifier})
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
        identifier = helper.decode_jwt(reset_token)["sub"]
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


@csrf_exempt
def issue_id_token(request: HttpRequest) -> JsonResponse:
    if request.method not in ("POST",):
        return JsonResponse({"message": "Method Not Allowed."}, status=405)

    try:
        if request.content_type == "application/json":
            data = json.load(request)
        else:
            data = QueryDict(request.POST.urlencode())

        serializer = IdentitySerializer(data=data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data
    except Exception as e:
        logging.warning(str(e))
        raise PermissionDenied

    qs = User.objects.select_related("user_profile").filter(username=validated_data["email"])
    if not qs.exists():
        raise PermissionDenied

    user: User = qs[0]
    if not user.check_password(validated_data["password"]):
        raise PermissionDenied

    id_token = helper.generate_id_token(user)

    return JsonResponse({"id_token": id_token}, status=200)
