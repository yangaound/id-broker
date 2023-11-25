from django.contrib.auth.models import User
from rest_framework import serializers


class ChangePasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, allow_blank=False, min_length=6)
    new_password = serializers.CharField(write_only=True, required=True, allow_blank=False, min_length=6)

    class Meta:
        model = User
        fields = ["password", "new_password"]
