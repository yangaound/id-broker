import jwt
from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.db import transaction
from django.http.request import HttpRequest
from django.http.response import HttpResponseRedirect
from requests_oauthlib import OAuth2Session

from id_broker.account.models import UserProfile


def oauth2_auth_rdr(request, id_provider):
    conf = settings.OAUTH2[id_provider.lower()]
    oauth = OAuth2Session(
        conf["client_id"],
        redirect_uri=conf["redirect_uri"],
        scope=conf["scope"],
        state=request.GET.get("next", settings.LOGIN_REDIRECT_URL),
    )
    authorization_url, state = oauth.authorization_url(
        conf["auth_uri"],
        request.GET.get("next", ""),
        access_type="offline",
        prompt="consent",
    )
    return HttpResponseRedirect(authorization_url)


@transaction.atomic
def oauth2_callback(request: HttpRequest, id_provider: str) -> HttpResponseRedirect:
    id_provider_name = id_provider.lower()
    conf = settings.OAUTH2[id_provider_name]

    # Request access token
    try:
        oauth = OAuth2Session(conf["client_id"], redirect_uri=conf["redirect_uri"])
        idp_resp = oauth.fetch_token(
            conf["token_uri"],
            code=request.GET.get("code"),
            client_secret=conf["client_secret"],
        )
    except Exception as e:
        return HttpResponseRedirect(f"/federal-web/signin-error-page?error={e}&stage=request")

    # Extract id token
    try:
        username, first_name, last_name, email, preferred_name, verified = _extract_open_info_from_id_token(
            idp_resp["id_token"],
            id_provider_name,
        )
    except Exception as e:
        return HttpResponseRedirect(f"/federal-web/signin-error-page?error={e}&stage=extract")

    # Update info from id token
    try:
        qs = UserProfile.objects.select_related("user").filter(user__username=username)
        if qs.exists():
            user_profile: UserProfile = qs[0]
            user_profile.preferred_name = preferred_name

            user: User = user_profile.user
            user.first_name = first_name
            user.last_name = last_name
            user.email = email
            user.is_active = verified

            user.save()
            user_profile.save()
        else:
            user = User(
                username=username,
                first_name=first_name,
                last_name=last_name,
                email=email,
                is_active=verified,
            )
            user_profile = UserProfile(
                user=user,
                preferred_name=preferred_name,
                id_provider=id_provider_name,
            )

            user.save()
            user_profile.save()

        login(
            request,
            user,
            backend="django.contrib.auth.backends.ModelBackend",
        )
    except Exception as e:
        return HttpResponseRedirect(f"/federal-web/signin-error-page?error={e}&stage=update")

    return HttpResponseRedirect(request.GET.get("state") or "/")


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
        verified = True

    elif id_provider_name == "line":
        username = open_info["sub"]
        first_name = ""
        last_name = ""
        email = open_info.get("email", "")
        preferred_name = open_info["name"]
        verified = True
    else:
        raise Exception(f"provider {id_provider_name} was not integrated")

    return username, first_name, last_name, email, preferred_name, verified
