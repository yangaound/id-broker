from typing import Union

from django.contrib.auth.models import User
from rest_framework import serializers

from .models import UserDraft


class ReprProfileMixin:
    @staticmethod
    def to_representation(instance: Union[User, UserDraft]) -> dict:
        user_profile = {
            "id": instance.pk,
            "user_identifier": instance.username,
            "id_provider_name": instance.user_profile.id_provider,
            "full_name": instance.get_full_name() or instance.user_profile.preferred_name,
            "confirmed": instance.is_active,
            "email": instance.email,
            "first_name": instance.first_name,
            "last_name": instance.last_name,
        }
        return user_profile


class RetrieveProfileSerializer(ReprProfileMixin, serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    user_identifier = serializers.CharField(read_only=True)
    id_provider_name = serializers.CharField(read_only=True)
    full_name = serializers.CharField(read_only=True)
    confirmed = serializers.BooleanField(read_only=True)
    email = serializers.EmailField(read_only=True, allow_null=True, allow_blank=True)
    first_name = serializers.CharField(read_only=True, required=False, default="")
    last_name = serializers.CharField(read_only=True, required=False, default="")

    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass


class IdentitySerializer(serializers.Serializer):
    email = serializers.EmailField(write_only=True)
    password = serializers.CharField(write_only=True, max_length=50, min_length=6)

    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass


class CreateIdentitySerializer(ReprProfileMixin, IdentitySerializer):
    first_name = serializers.CharField(required=False, allow_blank=True, default="")
    last_name = serializers.CharField(required=False, allow_blank=True, default="")


class UpdateUserInfoSerializer(ReprProfileMixin, serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["first_name", "last_name"]


class PerformAccountConfirmationSerializer(serializers.Serializer):
    verification_code = serializers.CharField()
    activate_token = serializers.CharField()
