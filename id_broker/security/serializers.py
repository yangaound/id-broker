from django.contrib.auth.models import User
from rest_framework import serializers


class ChangePasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, allow_blank=False, min_length=6)
    new_password = serializers.CharField(write_only=True, required=True, allow_blank=False, min_length=6)

    class Meta:
        model = User
        fields = ["password", "new_password"]


class ActivatePasswordResetSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = ["email"]


class PerformPasswordResetSerializer(serializers.Serializer):
    verification_code = serializers.CharField(max_length=12, min_length=1)
    reset_token = serializers.CharField(max_length=50, min_length=1)
    new_password = serializers.CharField(max_length=50, min_length=6)
