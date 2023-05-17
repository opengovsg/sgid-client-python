from datetime import datetime
from sgid_client import IdTokenVerifier
import json
from base64 import b64decode
from urllib.parse import unquote


def validate_access_token(access_token: str):
    if type(access_token) is not str or access_token == "":
        raise Exception(
            "sgID token endpoint did not return a valid access token. Expected a non-empty string."
        )


def validate_id_token(
    id_token: str,
    hostname: str,
    client_id: str,
    nonce: str | None,
    verifier: IdTokenVerifier.IdTokenVerifier,
) -> str:
    id_token_components = id_token.split(".")
    if len(id_token_components) != 3:
        raise Exception(
            "sgID server returned a malformed ID token which did not contain the expected components (header, payload, signature)"
        )
    try:
        header = json.loads(unquote(b64decode(id_token_components[0])))
        payload = json.loads(unquote(b64decode(id_token_components[1])))
    except:
        raise Exception("ID token header or payload was malformed")
    print(header)
    print(payload)
    validate_id_token_header(id_token_header=header)
    validate_id_token_payload(
        id_token_payload=payload, hostname=hostname, client_id=client_id, nonce=nonce
    )
    verifier.verify_jwt(id_token)
    return payload["sub"]


def validate_id_token_header(id_token_header: dict) -> None:
    received_alg = id_token_header.get("alg", None)
    if received_alg != "RS256":
        raise Exception(
            f"Unexpected signing algorithm used for ID token; expected 'RS256', got '{received_alg}'"
        )


def validate_id_token_payload(
    id_token_payload: dict,
    hostname: str,
    client_id: str,
    nonce: str | None = None,
) -> None:
    # Check that all required keys are present
    required_keys = ["iss", "sub", "aud", "exp", "iat"]
    missing_keys = []
    for required_key in required_keys:
        if required_key not in id_token_payload:
            missing_keys.append(required_key)
    if len(missing_keys) > 0:
        raise Exception(
            f"ID token payload did not contain the following mandatory keys: {','.join(missing_keys)}"
        )

    if id_token_payload["iss"] != hostname:
        raise Exception(
            f"ID token 'iss' did not match expected value. Expected '{hostname}', got '{id_token_payload['iss']}'"
        )

    if type(id_token_payload["iat"]) is not int:
        raise Exception(
            f"ID token 'iat' is invalid. Expected a valid number, got '{id_token_payload['iat']}'"
        )

    if type(id_token_payload["exp"]) is not int:
        raise Exception(
            f"ID token 'exp' is invalid. Expected a valid number, got '{id_token_payload['exp']}'"
        )

    curr_time = datetime.now()
    if id_token_payload["exp"] < curr_time.timestamp():
        raise Exception(
            f"ID token is expired. Current timestamp is {curr_time.strftime('%Y/%m/%d, %H:%M:%S')}, ID token expired at {datetime.fromtimestamp(id_token_payload['exp']).strftime('%Y/%m/%d, %H:%M:%S')}"
        )

    if id_token_payload["aud"] != client_id:
        raise Exception(
            f"ID token 'aud' did not match client ID. Expected '{client_id}', got '{id_token_payload['aud']}'"
        )

    nonce_received = id_token_payload.get("nonce", None)
    if nonce is not None and nonce_received != nonce:
        raise Exception(
            f"ID token 'nonce' did not match the nonce passed to the callback function. Expected '{nonce}', got '{nonce_received}'"
        )

    if type(id_token_payload["sub"]) is not str or id_token_payload["sub"] == "":
        raise Exception(
            f"ID token 'sub' is invalid. Expected a non-empty string, got '{id_token_payload['sub']}'"
        )
