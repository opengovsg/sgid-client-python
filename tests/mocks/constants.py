import json
from typing import TypedDict
import os

mock_dir = os.path.dirname(__file__)

mock_client_keys_file = open(os.path.join(mock_dir, "mockClientKeys.json"))
mock_private_key_pkcs1 = open(os.path.join(mock_dir, "mockPrivateKeyPkcs1.pem"))
mock_private_key_pkcs8 = open(os.path.join(mock_dir, "mockPrivateKeyPkcs8.pem"))
mock_jwks_file = open(os.path.join(mock_dir, "mockPublicJwks.json"))

mock_client_keys = json.load(mock_client_keys_file)
mock_jwks = json.load(mock_jwks_file)


hostname = "https://id.sgid.com"


class MockConstants(TypedDict):
    server: dict[str, str]
    client: dict[str, str]
    data: dict[str, any]


MOCK_CONSTANTS: MockConstants = {
    "server": {
        # private_key and public_jwks are a matching pair
        "private_key": mock_private_key_pkcs1.read(),
        "public_jwks": mock_jwks,
        "hostname": hostname,
        "auth_endpoint": f"{hostname}/v2/oauth/authorize",
        "token_endpoint": f"{hostname}/v2/oauth/token",
        "userinfo_endpoint": f"{hostname}/v2/oauth/userinfo",
        "jwks_endpoint": f"{hostname}/v2/.well-known/jwks.json",
    },
    "client": {
        "client_id": "mockClientId",
        "client_secret": "mockClientSecret",
        "redirect_uri": "https://sgid.com/callback",
        "public_key": mock_client_keys["publicKey"],
        "private_key": mock_client_keys["privateKey"],
        "private_key_pkcs8": mock_private_key_pkcs8.read(),
    },
    "data": {
        "block_key": {
            "kty": "oct",
            "alg": "A128GCM",
            "k": "kMnXcwOisOQskMlIu5oqVA",
        },
        "sub": "mockSub",
        "auth_code": "mockAuthCode",
        "access_token": "mockAccessToken",
        "userinfo": {
            "myKey": "myValue",
        },
        "code_verifier": "bbGcObXZC1YGBQZZtZGQH9jsyO1vypqCGqnSU_4TI5S",
        "code_challenge": "zaqUHoBV3rnhBF2g0Gkz1qkpEZXHqi2OrPK1DqRi-Lk",
    },
}

mock_client_keys_file.close()
mock_private_key_pkcs1.close()
mock_private_key_pkcs8.close()
mock_jwks_file.close()
