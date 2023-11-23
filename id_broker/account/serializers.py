from typing import Union

from django.contrib.auth.models import User
from rest_framework import serializers

from .models import UserDraft


class ReprMixin:
    @staticmethod
    def to_representation(instance: Union[User, UserDraft]):
        user_profile = {
            "id": instance.pk,
            "user_identifier": instance.username,
            "first_name": instance.first_name,
            "last_name": instance.last_name,
            "full_name": instance.get_full_name() or instance.user_profile.preferred_name,
            "email": instance.email,
            "confirmed": instance.is_active,
            "id_provider_name": instance.user_profile.id_provider,
        }
        return user_profile


class IdentitySerializer(serializers.Serializer):
    email = serializers.EmailField(help_text="*required")
    password = serializers.CharField(max_length=50, min_length=6, help_text="*required")

    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass


class CreateIdentitySerializer(ReprMixin, IdentitySerializer):
    first_name = serializers.CharField(required=False, allow_null=True)
    last_name = serializers.CharField(required=False, allow_null=True)


class UpdateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["first_name", "last_name"]


class ChangePasswordSerializer(serializers.ModelSerializer):
    new_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["password", "new_password"]


class RetrieveIdentitySerializer(ReprMixin, serializers.Serializer):
    identity = serializers.CharField()
    email = serializers.EmailField()
    first_name = serializers.CharField(required=False, allow_null=True)
    last_name = serializers.CharField(required=False, allow_null=True)

    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass
