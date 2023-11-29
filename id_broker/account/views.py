import logging
import traceback

from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.http import HttpRequest, HttpResponseRedirect
from django.shortcuts import render
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import AuthenticationFailed, ValidationError
from rest_framework.mixins import CreateModelMixin, RetrieveModelMixin, UpdateModelMixin
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.serializers import Serializer
from rest_framework.status import HTTP_200_OK
from rest_framework.viewsets import GenericViewSet

from id_broker import helper
from id_broker.account.models import UserDraft, UserProfile
from id_broker.account.serializers import (
    CreateIdentitySerializer,
    IdentitySerializer,
    PerformAccountConfirmationSerializer,
    RetrieveProfileSerializer,
    UpdateUserInfoSerializer,
)


class IDProfile(GenericViewSet, RetrieveModelMixin):
    serializer_class = RetrieveProfileSerializer
    queryset = User.objects.all()
    authentication_classes = (helper.IdTokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)

    def retrieve(self, request: Request, *args, **kwargs) -> Response:
        return Response(self.serializer_class(request.user, context=self.get_serializer_context()).data)


class IDRegister(GenericViewSet, CreateModelMixin):
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
            raise ValidationError({"email": ["This email was registered; please use forgot password to reset it."]})

        user_profile = UserProfile(
            id_provider=helper.BUILTIN_USER_POOL,
            preferred_name="{first_name} {last_name}".format(**validated_data).strip(),
        )
        user_profile.save()

        user_draft = UserDraft(user_profile=user_profile, **validated_data)
        user_draft.username = validated_data["email"]
        user_draft.set_password(validated_data["password"])
        user_draft.save()

        activate_token = default_token_generator.make_token(user_draft)
        verification_code = helper.pk_to_base36(user_draft.pk)

        try:
            self._send_conform_account_email(activate_token, verification_code, user_draft)
        except Exception:
            logging.error(traceback.format_exc())
            raise

        serializer = self.get_serializer(user_draft)
        headers = self.get_success_headers(serializer.data)

        return Response(serializer.data, headers=headers)

    @staticmethod
    def _send_conform_account_email(activate_token: str, verification_code: str, user_draft: UserDraft):
        confirm_email_content = settings.ACCOUNT_CONFIRM_EMAIL_CONTENT.format(
            first_name=user_draft.first_name,
            activate_token=activate_token,
            verification_code=verification_code,
        )
        send_mail(
            settings.ACCOUNT_CONFIRM_EMAIL_SUBJECT,
            confirm_email_content,
            from_email=settings.EMAIL_SENDER,
            recipient_list=[user_draft.email],
            fail_silently=False,
        )


class UpdateUserInfoViews(GenericViewSet, UpdateModelMixin):
    serializer_class = UpdateUserInfoSerializer
    queryset = User.objects.select_related("user_profile").all()
    authentication_classes = (helper.IdTokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)

    def partial_update(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data

        user: User = request.user
        user.first_name = validated_data.get("first_name") or user.first_name
        user.last_name = validated_data.get("last_name") or user.last_name
        user.save()

        return Response(validated_data)


class ClientPasswordLogin(GenericViewSet, UpdateModelMixin):
    serializer_class = IdentitySerializer
    queryset = User.objects.select_related("user_profile").all()
    permission_classes = ()

    def partial_update(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data

        qs = User.objects.filter(username=validated_data["email"])
        if not qs.exists():
            logging.warning("The email '{email}' does not exist.".format(**validated_data))
            raise AuthenticationFailed

        user = qs.first()
        if not user.check_password(validated_data["password"]):
            logging.warning("Incorrect password entered for user '{email}'.".format(**validated_data))
            raise AuthenticationFailed

        login(request, user)
        return Response(status=HTTP_200_OK)


class PerformAccountConfirmationViews(GenericViewSet, RetrieveModelMixin):
    serializer_class = Serializer
    permission_classes = ()

    def retrieve(self, request: Request, *args, **kwargs) -> HttpResponseRedirect:
        serializer = PerformAccountConfirmationSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data

        try:
            _ = self._perform_account_confirmation(
                validated_data["verification_code"], validated_data["activate_token"]
            )
            next_page = request.query_params.get("next") or "/"
        except ValueError as e:
            next_page = helper.add_query_params_into_url(
                original_url=request.query_params.get("error_page") or "/",
                new_params={"error": str(e)},
            )

        return HttpResponseRedirect(next_page)

    @staticmethod
    def _perform_account_confirmation(verification_code: str, activate_token: str):
        try:
            user_draft_pk = helper.base36_to_pk(verification_code)
        except ValueError:
            raise ValueError("Invalid activate_token or verification_code")

        if not 0 < user_draft_pk < helper.MAX_PK_NUMBER:
            raise ValueError("Invalid activate_token or verification_code")

        try:
            user_draft: UserDraft = UserDraft.objects.select_related("user_profile").get(pk=user_draft_pk)
        except UserDraft.DoesNotExist:
            logging.error(
                f"Received invalid profile id `{verification_code}` encoded from user_draft id `{user_draft_pk}`"
            )
            raise ValueError("Invalid activate_token or verification_code")

        if not default_token_generator.check_token(user_draft, activate_token):
            raise AuthenticationFailed("Invalid or expired token")

        qs = User.objects.filter(username=user_draft.username)
        if not qs.exists():
            user = User(
                username=user_draft.username,
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


def render_federal_signin_page(req: HttpRequest):
    base_url = helper.build_base_path(req)
    return render(req, "federal_signin.html", context={"baseURL": base_url})


def render_federal_oauth2_signin_error_page(req: HttpRequest):
    base_url = helper.build_base_path(req)
    return render(req, "oauth2_signin_error.html", context={"baseURL": base_url})
