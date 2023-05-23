import secrets
from typing import NamedTuple
from urllib.parse import urlparse, urlencode
import requests
from .validation import validate_access_token, validate_id_token
from .IdTokenVerifier import IdTokenVerifier
from .decrypt_data import decrypt_data
from .error import Errors, get_network_error_message, get_www_authenticate_error_message
from .util import convert_to_pkcs8

API_VERSION = 2
SGID_RESPONSE_TYPE = "code"
SGID_CODE_CHALLENGE_METHOD = "S256"
SGID_GRANT_TYPE = "authorization_code"


class AuthorizationUrlReturn(NamedTuple):
    url: str
    nonce: str | None


class CallbackReturn(NamedTuple):
    sub: str
    access_token: str


class UserInfoReturn(NamedTuple):
    sub: str
    data: dict


class SgidClient:
    """Class which allows you to interact with the sgID API."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        private_key: str,
        redirect_uri: str | None = None,
        hostname: str = "https://api.id.gov.sg",
    ):
        """Initialises an SgidClient instance.

        Args:
            client_id (str): Client ID provided during client registration.

            client_secret (str): Client secret provided during client registration.

            private_key (str): Client private key provided during client registration.

            redirect_uri (str | None, optional): Redirection URI for user to return to your
            application after login. If not provided in the constructor, this must
            be provided to the authorization_url and callback functions. Defaults to None.

            hostname (str, optional): Hostname of OpenID provider (sgID). Defaults to "https://api.id.gov.sg".

        Raises:
            Exception: if private key is invalid.
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.private_key = convert_to_pkcs8(private_key)
        self.redirect_uri = redirect_uri
        self.issuer = f"{urlparse(hostname).geturl()}/v{API_VERSION}"
        self.verifier = IdTokenVerifier(jwks_uri=f"{self.issuer}/.well-known/jwks.json")

    def authorization_url(
        self,
        code_challenge: str,
        state: str | None = None,
        redirect_uri: str | None = None,
        scope: str | list[str] = "openid myinfo.name",
        nonce: str | None = secrets.token_urlsafe(32),
    ) -> AuthorizationUrlReturn:
        """Generates authorization url to redirect end-user to sgID login page.

        Args:
            code_challenge (str): The code challenge generated from generate_pkce_pair().

            state (str | None, optional): A string which will be passed back to your application once
            the end-user logs in. You can also use this to track per-request state. Defaults to None.

            redirect_uri (str | None, optional): The redirect URI used in the authorization
            request. If this param is provided, it will be used instead of the redirect
            URI provided in the SgidClient constructor. If not provided in the constructor,
            the redirect URI must be provided here. Defaults to None.

            scope (str | list[str], optional): "openid" must be provided as a
            scope. Defaults to "openid myinfo.name".

            nonce (str | None, optional): Unique nonce for this request. If this param is
            not provided, a nonce is generated and returned. To prevent this behaviour,
            specify None for this param. Defaults to `secrets.token_urlsafe(32)`.

        Raises:
            Exception: if redirect URI is provided in neither the constructor nor this function.

        Returns:
            AuthorizationUrlReturn: authorization URL and nonce.
        """
        if redirect_uri is None and self.redirect_uri is None:
            raise Exception(Errors.MISSING_REDIRECT_URI)
        params = {
            "client_id": self.client_id,
            "scope": " ".join(scope) if isinstance(scope, list) else scope,
            "redirect_uri": self.redirect_uri if redirect_uri is None else redirect_uri,
            "response_type": SGID_RESPONSE_TYPE,
            "code_challenge": code_challenge,
            "code_challenge_method": SGID_CODE_CHALLENGE_METHOD,
        }
        if state is not None:
            params["state"] = state
        if nonce is not None:
            params["nonce"] = nonce
        auth_url = f"{self.issuer}/oauth/authorize?{urlencode(params)}"
        return AuthorizationUrlReturn(url=auth_url, nonce=nonce)

    def callback(
        self,
        code: str,
        code_verifier: str,
        nonce: str | None = None,
        redirect_uri: str | None = None,
    ) -> CallbackReturn:
        """Exchanges authorization code for access token.

        Args:
            code (str): The authorization code received from the authorization server.

            code_verifier (str): The code verifier corresponding to the code challenge
            that was passed to `authorization_url` for this request.

            nonce (str | None, optional): Nonce passed to `authorization_url` for this
            request. Specify None if no nonce was passed to `authorization_url`.
            Defaults to None.

            redirect_uri (str | None, optional): The redirect URI used in the
            authorization request. If not specified, defaults to the one passed
            to the SgidClient constructor.

        Raises:
            Exception: if call to token endpoint fails.
            Exception: if call to JWKS endpoint fails.
            Exception: if ID token validation fails.
            Exception: if access token validation fails.

        Returns:
            CallbackReturn: The sub (subject identifier claim) of the user and
            access token. The subject identifier claim is the end-user's unique ID.
        """
        url = f"{self.issuer}/oauth/token"
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri if redirect_uri is None else redirect_uri,
            "code": code,
            "grant_type": SGID_GRANT_TYPE,
            "code_verifier": code_verifier,
        }
        res = requests.post(url, data)
        if res.status_code != 200:
            error_message = get_network_error_message(
                message=Errors.TOKEN_ENDPOINT_FAILED,
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
        return CallbackReturn(sub=sub, access_token=access_token)

    def userinfo(self, sub: str, access_token: str) -> UserInfoReturn:
        """Retrieves verified user info and decrypts it with your private key.

        Args:
            sub (str): The sub returned from the `callback` function.

            access_token (str): The access token returned from the `callback` function.

        Raises:
            Exception: if call to userinfo endpoint fails.
            Exception: if sub returned from userinfo endpoint does not match
            sub passed to this function.
            Exception: if decryption fails.

        Returns:
            UserInfoReturn: The sub of the end-user and the end-user's verified data.
            The subreturned is the same as the one passed in the params.
        """
        url = f"{self.issuer}/oauth/userinfo"
        headers = {
            "Authorization": f"Bearer {access_token}",
        }
        res = requests.get(url, headers=headers)
        if res.status_code != 200:
            error_message = get_www_authenticate_error_message(
                message=Errors.USERINFO_ENDPOINT_FAILED, res=res
            )
            raise Exception(error_message)
        res_body = res.json()
        if res_body["sub"] != sub:
            raise Exception(Errors.USERINFO_SUB_MISMATCH)
        decrypted_data = decrypt_data(
            encrypted_key=res_body["key"],
            encrypted_data=res_body["data"],
            private_key=self.private_key,
        )
        return UserInfoReturn(sub=res_body["sub"], data=decrypted_data)
