import logging
import traceback

from django.conf import settings
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.middleware.csrf import get_token
from rest_framework import mixins, permissions, viewsets
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied, ValidationError
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.serializers import Serializer

from id_broker import helper
from id_broker.account.serializers import IdentitySerializer

from .serializers import ActivatePasswordResetSerializer, ChangePasswordSerializer, PerformPasswordResetSerializer


class RetrieveCsrfTokenViews(viewsets.GenericViewSet, mixins.RetrieveModelMixin):
    serializer_class = Serializer
    permission_classes = ()

    def retrieve(self, request: Request, *args, **kwargs) -> Response:
        csrftoken = get_token(request)
        res = Response({settings.CSRF_COOKIE_NAME: csrftoken})
        res.set_cookie(settings.CSRF_COOKIE_NAME, csrftoken)
        return res


class RequestIDTokenViews(viewsets.GenericViewSet, mixins.CreateModelMixin):
    serializer_class = IdentitySerializer
    permission_classes = ()

    def create(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data

        qs = User.objects.select_related("user_profile").filter(username=validated_data["email"])
        if not qs.exists():
            raise AuthenticationFailed

        user: User = qs[0]
        if not user.check_password(validated_data["password"]):
            raise AuthenticationFailed

        id_token = helper.generate_id_token(user)

        return Response({"id_token": id_token})


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
            raise AuthenticationFailed

        user.set_password(validated_data["new_password"])
        user.save()

        return Response(status=200)


class ActivatePasswordResetViews(viewsets.GenericViewSet, mixins.UpdateModelMixin):
    serializer_class = ActivatePasswordResetSerializer
    queryset = User.objects.select_related("user_profile").all()
    permission_classes = ()

    def partial_update(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data

        try:
            user: User = User.objects.get(username=validated_data["email"])
        except User.DoesNotExist:
            raise ValidationError({"email": ["Cannot recognize!"]})

        verification_code = helper.generate_verification_code()
        reset_passwd_token = helper.encode_jwt({"sub": user.pk})
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

        return Response({"message": "Password reset processing is activated now. Please check your email."})


class PerformPasswordResetViews(viewsets.GenericViewSet, mixins.UpdateModelMixin):
    serializer_class = PerformPasswordResetSerializer
    queryset = User.objects.select_related("user_profile").all()
    permission_classes = ()

    def partial_update(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data

        verification_code = validated_data["verification_code"]
        reset_token = validated_data["reset_token"]
        new_password = validated_data["new_password"]

        try:
            user_pk = helper.decode_jwt(reset_token)["sub"]
            user: User = User.objects.select_related("user_profile").get(
                pk=user_pk, user_profile__verification_code=verification_code
            )
        except Exception as e:
            logging.warning(str(e))
            raise AuthenticationFailed

        _microseconds = int(helper.generate_verification_code())
        if 60 * 60 * 25 * 1 * 1000000 < _microseconds - int(verification_code):
            raise PermissionDenied("Expired.")

        user.set_password(new_password)
        user.save()

        return Response({"message": f"Your password has been reset."})
