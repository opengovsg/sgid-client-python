import json
from .constants import MOCK_CONSTANTS
from datetime import datetime
import math
from jwcrypto import jwt, jwk
from Crypto.PublicKey import RSA
from base64 import urlsafe_b64encode


def create_id_token(
    nonce=None,
    iss=MOCK_CONSTANTS["server"]["hostname"] + "/v2",
    sub=MOCK_CONSTANTS["data"]["sub"],
    aud=MOCK_CONSTANTS["client"]["client_id"],
    exp=math.ceil(datetime.now().timestamp() + 10),
    iat=math.ceil(datetime.now().timestamp()),
    header={"alg": "RS256"},
    delete_keys=[],
    private_key=MOCK_CONSTANTS["server"]["private_key"],
) -> str:
    private_key_pkcs8 = RSA.import_key(extern_key=private_key).export_key(pkcs=8)
    private_key_jwk = jwk.JWK.from_pem(private_key_pkcs8)
    claims = {
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "exp": exp,
        "iat": iat,
    }
    if nonce is not None:
        claims["nonce"] = nonce
    for dk in delete_keys:
        del claims[dk]
    raw_jwt = jwt.JWT(header=header, claims=claims)
    raw_jwt.make_signed_token(key=private_key_jwk)
    return raw_jwt.serialize()


def make_base64url_json(content: dict) -> str:
    return urlsafe_b64encode(bytearray(json.dumps(content), encoding="utf-8")).decode(
        "utf-8"
    )
