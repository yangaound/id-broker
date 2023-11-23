from rest_framework import serializers


class ReprMixin:
    @staticmethod
    def to_representation(instance):
        user_profile = {
            "id": instance.id,
            "user_identifier": instance.username,
            "first_name": instance.first_name,
            "last_name": instance.last_name,
            "email": instance.email,
            "confirmed": instance.is_active,
            "preferred_name": instance.user_profile.preferred_name if hasattr(instance, "user_profile") else None,
            "id_provider_name": instance.user_profile.id_provider if hasattr(instance, "user_profile") else None,
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


class RetrieveIdentitySerializer(ReprMixin, serializers.Serializer):
    identity = serializers.CharField()
    email = serializers.EmailField()
    first_name = serializers.CharField(required=False, allow_null=True)
    last_name = serializers.CharField(required=False, allow_null=True)

    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass
