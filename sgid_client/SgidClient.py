import secrets
from typing import TypedDict
import urllib
from urllib.parse import urlparse, urlencode
from collections import namedtuple


class AuthorizationUrlReturn(TypedDict):
    url: str
    nonce: str | None


class CallbackReturn(TypedDict):
    sub: str
    access_token: str


class UserInfoReturn(TypedDict):
    sub: str
    data: dict


class SgidClient:
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        private_key: str,
        redirect_uri: str | None,
        hostname: str = "https://api.id.gov.sg",
        api_version: int = 1,
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.private_key = private_key
        self.redirect_uri = redirect_uri
        self.hostname = urlparse(hostname).geturl()
        self.api_version = api_version

    def authorization_url(
        self,
        state: str,
        redirect_uri: str | None = None,
        scope: str | list[str] = "openid myinfo.name",
        nonce: str | None = secrets.token_urlsafe(32),
    ) -> AuthorizationUrlReturn:
        if redirect_uri is None and self.redirect_uri is None:
            raise Exception(
                "No redirect URI registered with this client. You must either specify a valid redirect URI in the SgidClient constructor, or pass it to the authorizationUrl and callback functions."
            )
        params = {
            "client_id": self.client_id,
            "scope": " ".join(scope) if isinstance(scope, list) else scope,
            "redirect_uri": self.redirect_uri if redirect_uri is None else redirect_uri,
            "response_type": "code",
            "state": state,
        }
        if nonce is not None:
            params["nonce"] = nonce
        return (
            self.hostname
            + "/v"
            + str(self.api_version)
            + "/oauth/authorize?"
            + urlencode(params)
        )

    def callback(self, code: str, nonce: str = None) -> CallbackReturn:
        pass

    def userinfo(self, access_token: str) -> UserInfoReturn:
        pass
