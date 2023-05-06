import secrets
from typing import TypedDict, Union


class AuthorizationUrlReturn(TypedDict):
    url: str
    nonce: Union[str, None]


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
        redirect_uri: str,
        hostname: str = "https://api.id.gov.sg",
        api_version: int = 1,
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.private_key = private_key
        self.redirect_uri = redirect_uri
        self.hostname = hostname
        self.api_version = api_version

    def authorization_url(
        self, state: str, nonce: str = secrets.token_urlsafe(16)
    ) -> AuthorizationUrlReturn:
        pass

    def callback(self, code: str, nonce: str = None) -> CallbackReturn:
        pass

    def userinfo(self, access_token: str) -> UserInfoReturn:
        pass
