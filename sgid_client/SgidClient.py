import secrets
from typing import TypedDict
from urllib.parse import urlparse, urlencode
import requests
from .validation import validate_access_token, validate_id_token
from .IdTokenVerifier import IdTokenVerifier
from .decrypt_data import decrypt_data
from .error import Errors, get_network_error_message, get_www_authenticate_error_message
from .util import convert_to_pkcs8

API_VERSION = 2


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
        self.private_key = convert_to_pkcs8(private_key)
        self.redirect_uri = redirect_uri
        self.issuer = f"{urlparse(hostname).geturl()}/v{API_VERSION}"
        self.api_version = api_version
        self.verifier = IdTokenVerifier(jwks_uri=f"{self.issuer}/.well-known/jwks.json")

    def authorization_url(
        self,
        state: str,
        code_challenge: str,
        redirect_uri: str | None = None,
        scope: str | list[str] = "openid myinfo.name",
        nonce: str | None = secrets.token_urlsafe(32),
    ) -> AuthorizationUrlReturn:
        if redirect_uri is None and self.redirect_uri is None:
            raise Exception(Errors["MISSING_REDIRECT_URI"])
        params = {
            "client_id": self.client_id,
            "scope": " ".join(scope) if isinstance(scope, list) else scope,
            "redirect_uri": self.redirect_uri if redirect_uri is None else redirect_uri,
            "response_type": "code",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        if nonce is not None:
            params["nonce"] = nonce
        auth_url = f"{self.issuer}/oauth/authorize?{urlencode(params)}"
        return {
            "url": auth_url,
            "nonce": nonce,
        }

    def callback(
        self,
        code: str,
        code_verifier: str,
        nonce: str | None = None,
        redirect_uri: str | None = None,
    ) -> CallbackReturn:
        url = f"{self.issuer}/oauth/token"
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri if redirect_uri is None else redirect_uri,
            "code": code,
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
        }
        res = requests.post(url, data)
        if res.status_code != 200:
            error_message = get_network_error_message(
                message=Errors["TOKEN_ENDPOINT_FAILED"],
                status=res.status_code,
                body=res.text,
            )
            raise Exception(error_message)
        res_body = res.json()
        id_token: str = res_body["id_token"]
        access_token: str = res_body["access_token"]
        sub = validate_id_token(
            id_token=id_token,
            issuer=self.issuer,
            client_id=self.client_id,
            nonce=nonce,
            verifier=self.verifier,
        )
        validate_access_token(access_token=access_token)
        return {"sub": sub, "access_token": access_token}

    def userinfo(self, sub: str, access_token: str) -> UserInfoReturn:
        url = f"{self.issuer}/oauth/userinfo"
        headers = {
            "Authorization": f"Bearer {access_token}",
        }
        res = requests.get(url, headers=headers)
        if res.status_code != 200:
            error_message = get_www_authenticate_error_message(
                message=Errors["USERINFO_ENDPOINT_FAILED"], res=res
            )
            raise Exception(error_message)
        res_body = res.json()
        if res_body["sub"] != sub:
            raise Exception(Errors["USERINFO_SUB_MISMATCH"])
        decrypted_data = decrypt_data(
            encrypted_key=res_body["key"],
            encrypted_data=res_body["data"],
            private_key=self.private_key,
        )
        return {"data": decrypted_data, "sub": res_body["sub"]}
