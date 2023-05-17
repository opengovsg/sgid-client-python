from typing import TypedDict
import requests
from jwcrypto import jwk, jwt as jwt_lib


class IdTokenVerifier:
    def __init__(self, jwks_uri: str) -> None:
        self.jwks_cache = None
        self.jwks_uri = jwks_uri

    def _fetch_jwks_from_uri(self):
        res = requests.get(self.jwks_uri)
        if res.status_code != 200:
            error_message = f"sgID responded with an error at the jwks endpoint.\nResponse status: {res.status_code}\nResponse body: {res.text}"
            raise Exception(error_message)
        return jwk.JWKSet.from_json(res.text)

    def verify_jwt(self, jwt: str):
        if self.jwks_cache is None:
            self.jwks_cache = self._fetch_jwks_from_uri()
        try:
            jwt_lib.JWT(key=self.jwks_cache, jwt=jwt)
        except:
            # Try again in case jwks has refreshed
            self.jwks_cache = self._fetch_jwks_from_uri()
            try:
                jwt_lib.JWT(key=self.jwks_cache, jwt=jwt)
            except:
                raise Exception("ID token signature is invalid")
