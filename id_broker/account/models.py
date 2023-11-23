from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _


class UserProfile(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, related_name="user_profile"
    )
    id_provider = models.CharField(max_length=20, blank=True, null=True, default="builtin-user-pool")
    preferred_name = models.CharField(max_length=20)
    verification_code = models.CharField(max_length=20, null=True)
    created_time = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    updated_time = models.DateTimeField(auto_now=True, null=True, blank=True)

    def __str__(self):
        return f"UserProfile<id={self.id}, id_provider={self.id_provider}>"


class UserDraft(AbstractUser):
    user_profile = models.OneToOneField(UserProfile, on_delete=models.CASCADE, null=True)
    is_active = models.BooleanField(default=False)  # overwrite default to `False`
    groups = models.CharField(max_length=20, null=True, blank=True)  # overwrite
    user_permissions = models.CharField(max_length=20, null=True, blank=True)  # overwrite

    class Meta:
        verbose_name = _("user_draft")
        verbose_name_plural = _("user-drafts")

    def __str__(self):
        return f"UserDraft<username={self.username}, date_joined={self.date_joined}>"
