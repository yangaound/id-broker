import jwt
from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.db import transaction
from django.http.response import HttpResponseRedirect
from requests_oauthlib import OAuth2Session
from rest_framework import mixins, viewsets
from rest_framework.request import Request
from rest_framework.serializers import Serializer

from id_broker import helper
from id_broker.account.models import UserProfile


class Oauth2Authentication(viewsets.GenericViewSet, mixins.RetrieveModelMixin):
    authentication_classes = ()
    permission_classes = ()
    serializer_class = Serializer

    def retrieve(self, request: Request, id_provider: str, *args, **kwargs) -> HttpResponseRedirect:
        conf = settings.OAUTH2[id_provider]
        oauth = OAuth2Session(
            conf["client_id"],
            redirect_uri=conf["redirect_uri"],
            scope=conf["scope"],
            state=request.GET.get("next") or settings.LOGIN_REDIRECT_URL,
        )
        authorization_url, state = oauth.authorization_url(
            conf["auth_uri"],
            request.GET.get("next", ""),
            access_type="offline",
            prompt="consent",
        )
        return HttpResponseRedirect(authorization_url)

    retrieve.__doc__ = "Configured ID Providers: " + ", ".join(settings.OAUTH2.keys())


class Oauth2Callback(viewsets.GenericViewSet, mixins.RetrieveModelMixin):
    authentication_classes = ()
    permission_classes = ()
    serializer_class = Serializer

    @transaction.atomic
    def retrieve(self, request: Request, id_provider: str, *args, **kwargs) -> HttpResponseRedirect:
        id_provider_name = id_provider.lower()
        conf = settings.OAUTH2[id_provider_name]
        base_path = helper.build_base_path(request)

        # Request access token
        try:
            code = request.query_params.get("code")
            if not code:
                raise RuntimeError("Please supply authorization_code.")

            oauth = OAuth2Session(conf["client_id"], redirect_uri=conf["redirect_uri"])
            idp_resp = oauth.fetch_token(
                conf["token_uri"],
                code=request.GET.get("code"),
                client_secret=conf["client_secret"],
            )
        except Exception as e:
            return HttpResponseRedirect(f"{base_path}/accounts/oauth2-signin-error?error={e}&stage=request")

        # Extract id token
        try:
            username, first_name, last_name, email, preferred_name, verified = _extract_open_info_from_id_token(
                idp_resp["id_token"],
                id_provider_name,
            )
        except Exception as e:
            return HttpResponseRedirect(f"{base_path}/accounts/oauth2-signin-error?error={e}&stage=extract")

        # Update info from id token
        try:
            qs = UserProfile.objects.select_related("user").filter(user__username=username)
            if qs.exists():
                user_profile: UserProfile = qs[0]
                user_profile.preferred_name = preferred_name

                user: User = user_profile.user
                user.first_name = first_name or user.first_name
                user.last_name = last_name or user.last_name
                user.email = email or user.email
                user.is_active = True if verified in (None, True) else False

                user.save()
                user_profile.save()
            else:
                user = User(
                    username=username,
                    first_name=first_name,
                    last_name=last_name,
                    email=email,
                    is_active=True if verified in (None, True) else False,
                )
                user_profile = UserProfile(
                    user=user,
                    preferred_name=preferred_name,
                    id_provider=id_provider_name,
                )

                user.save()
                user_profile.save()

            login(request, user)
            app_id_token = helper.generate_id_token(user)
        except Exception as e:
            return HttpResponseRedirect(f"{base_path}/accounts/oauth2-signin-error?error={e}&stage=update")

        next_page = helper.add_query_params_into_url(
            original_url=request.GET.get("state", "/"),
            new_params={"id_token": app_id_token},
        )
        return HttpResponseRedirect(next_page)


def _extract_open_info_from_id_token(id_token: str, id_provider_name: str) -> tuple:
    open_info = jwt.decode(id_token, options={"verify_signature": False})

    if id_provider_name == "google":
        username = open_info["sub"]
        first_name = open_info["given_name"]
        last_name = open_info["family_name"]
        email = open_info["email"]
        preferred_name = open_info["name"]
        verified = open_info["email_verified"]

    elif id_provider_name == "azure":
        username = open_info["sub"]
        first_name = ""
        last_name = ""
        email = open_info["email"]
        preferred_name = open_info["name"]
        verified = open_info.get("email_verified")

    elif id_provider_name == "line":
        username = open_info["sub"]
        first_name = ""
        last_name = ""
        email = open_info.get("email", "")
        preferred_name = open_info["name"]
        verified = open_info.get("email_verified")
    else:
        username = open_info["sub"]
        first_name = open_info.get("given_name") or ""
        last_name = open_info.get("family_name") or ""
        email = open_info.get("email") or ""
        preferred_name = open_info["name"]
        verified = open_info.get("email_verified")

    return username, first_name, last_name, email, preferred_name, verified
