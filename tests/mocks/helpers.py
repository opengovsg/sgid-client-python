import hashlib
import json
from .constants import MOCK_CONSTANTS
from typing import List
from datetime import datetime
import math
import responses
from jwcrypto import jwt, jwk, jwe
from Crypto.PublicKey import RSA
from base64 import urlsafe_b64encode
from sgid_client.SgidClient import SgidClient


def get_client(delete_args: List[str] = [], **kwargs):
    args = {
        "client_id": MOCK_CONSTANTS.client["client_id"],
        "client_secret": MOCK_CONSTANTS.client["client_secret"],
        "private_key": MOCK_CONSTANTS.client["private_key"],
        "redirect_uri": MOCK_CONSTANTS.client["redirect_uri"],
        "hostname": MOCK_CONSTANTS.server["hostname"],
    }
    for delete_arg in delete_args:
        del args[delete_arg]
    args.update(kwargs)
    return SgidClient(**args)


def create_id_token(
    nonce=None,
    iss=MOCK_CONSTANTS.server["hostname"] + "/v2",
    sub=MOCK_CONSTANTS.data["sub"],
    aud=MOCK_CONSTANTS.client["client_id"],
    exp=math.ceil(datetime.now().timestamp() + 10),
    iat=math.ceil(datetime.now().timestamp()),
    header={"alg": "RS256"},
    delete_keys=[],
    private_key=MOCK_CONSTANTS.server["private_key"],
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


def get_jwks_response(
    url=f"{MOCK_CONSTANTS.server['hostname']}/v2/.well-known/jwks.json",
    json=MOCK_CONSTANTS.server["public_jwks"],
):
    return responses.Response(method="GET", url=url, json=json)


def generate_encrypted_block_key():
    encryption_key = jwk.JWK.from_pem(
        MOCK_CONSTANTS.client["public_key"].encode("utf-8")
    )
    payload = json.dumps(MOCK_CONSTANTS.data["block_key"])
    encrypted = jwe.JWE(
        plaintext=payload,
        protected=json.dumps({"alg": "RSA-OAEP-256", "enc": "A256GCM"}),
    )
    encrypted.add_recipient(key=encryption_key)
    return encrypted.serialize()


def generate_user_info():
    result = {}
    encryption_key = jwk.JWK.from_json(json.dumps(MOCK_CONSTANTS.data["block_key"]))
    to_encrypt: dict[str, str] = MOCK_CONSTANTS.data["userinfo"]
    for k, v in to_encrypt.items():
        encrypted = jwe.JWE(
            plaintext=v, protected=json.dumps({"alg": "A128GCMKW", "enc": "A128GCM"})
        )
        encrypted.add_recipient(encryption_key)
        result[k] = encrypted.serialize()
    return result


def sha256_b64url(payload: str) -> str:
    payload_bytearray = bytearray(payload, encoding="utf-8")
    payload_hash = hashlib.sha256(payload_bytearray).digest()
    with_padding = urlsafe_b64encode(payload_hash).decode("utf-8")
    return with_padding.replace("=", "")
