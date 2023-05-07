import secrets
from typing import TypedDict
from urllib.parse import urlparse, urlencode, unquote
import requests
import json
from base64 import b64decode
from jwcrypto import jwk, jwe


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
        auth_url = (
            self.hostname
            + "/v"
            + str(self.api_version)
            + "/oauth/authorize?"
            + urlencode(params)
        )
        return {
            "url": auth_url,
            "nonce": nonce,
        }

    def callback(
        self, code: str, nonce: str | None = None, redirect_uri: str | None = None
    ) -> CallbackReturn:
        url = self.hostname + "/v" + str(self.api_version) + "/oauth/token"
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri if redirect_uri is None else redirect_uri,
            "code": code,
            "grant_type": "authorization_code",
        }
        res = requests.post(url, data)
        res_body = res.json()
        if res.status_code != 200:
            error_message = (
                "sgID responded with an error at the token endpoint.\n"
                + "Response status: "
                + res.status_code
                + "\nResponse body: "
                + json.dumps(res_body, indent=2)
            )
            raise Exception(error_message)
        id_token: str = res_body["id_token"]
        id_token_components = id_token.split(".")
        header = json.loads(unquote(b64decode(id_token_components[0])))
        payload = json.loads(unquote(b64decode(id_token_components[1])))
        signature = id_token_components[2]
        return {"sub": payload["sub"], "access_token": res_body["access_token"]}

    def userinfo(self, access_token: str) -> UserInfoReturn:
        url = self.hostname + "/v" + str(self.api_version) + "/oauth/userinfo"
        headers = {
            "Authorization": "Bearer " + access_token,
        }
        res = requests.get(url, headers=headers)
        res_body = res.json()
        if res.status_code != 200:
            error_message = (
                "sgID responded with an error at the token endpoint.\n"
                + "Response status: "
                + res.status_code
                + "\nResponse body: "
                + json.dumps(res_body, indent=2)
            )
            raise Exception(error_message)
        decrypted_data = self.decrypt_data(
            encrypted_key=res_body["key"], encrypted_data=res_body["data"]
        )
        return {"data": decrypted_data, "sub": res_body["sub"]}

    def decrypt_data(self, encrypted_key: str, encrypted_data: dict):
        # Load private_key
        private_key = jwk.JWK.from_pem(self.private_key.encode("utf-8"))
        jwe_key = jwe.JWE()

        # Decrypt encrypted_key to get block_key
        jwe_key.deserialize(encrypted_key, key=private_key)
        block_key_json = jwe_key.payload

        # Load block_key
        block_key = jwk.JWK.from_json(block_key_json.decode("utf-8").replace("'", '"'))
        jwe_data = jwe.JWE()

        # Initialise dict
        data_dict = {}

        for field in encrypted_data:
            # Decrypt encrypted_data[field] to get actual_data
            jwe_data.deserialize(encrypted_data[field], key=block_key)
            data_dict[field] = jwe_data.payload.decode("utf-8")

        return data_dict
