from datetime import datetime
from sgid_client import IdTokenVerifier
import json
from base64 import b64decode
from urllib.parse import unquote
from .error import (
    Errors,
    get_expected_vs_received_error_message,
    get_expiry_error_message,
)


def validate_access_token(access_token: str):
    if type(access_token) is not str or access_token == "":
        raise Exception(Errors.ACCESS_TOKEN_INVALID)


def validate_id_token(
    id_token: str,
    issuer: str,
    client_id: str,
    nonce: str | None,
    verifier: IdTokenVerifier.IdTokenVerifier,
) -> str:
    id_token_components = id_token.split(".")
    if len(id_token_components) != 3:
        raise Exception(Errors.ID_TOKEN_MALFORMED)
    try:
        # Avoid padding errors by appending the max possible padding.
        # b64decode will ignore any extra padding.
        header = json.loads(unquote(b64decode(id_token_components[0] + "==")))
        payload = json.loads(unquote(b64decode(id_token_components[1] + "==")))
    except:
        raise Exception(Errors.ID_TOKEN_HEADER_PAYLOAD_MALFORMED)
    validate_id_token_header(id_token_header=header)
    validate_id_token_payload(
        id_token_payload=payload, issuer=issuer, client_id=client_id, nonce=nonce
    )
    verifier.verify_jwt(id_token)
    return payload["sub"]


def validate_id_token_header(id_token_header: dict) -> None:
    received_alg = id_token_header.get("alg", None)
    if received_alg != "RS256":
        raise Exception(
            get_expected_vs_received_error_message(
                message=Errors.ID_TOKEN_WRONG_SIGNING_ALG,
                expected="RS256",
                received=received_alg,
            )
        )


def validate_id_token_payload(
    id_token_payload: dict,
    issuer: str,
    client_id: str,
    nonce: str | None = None,
) -> None:
    # Check that all required keys are present
    required_keys = ["iss", "sub", "aud", "exp", "iat"]
    present_keys = []
    for required_key in required_keys:
        if required_key in id_token_payload:
            present_keys.append(required_key)
    if len(present_keys) != len(required_keys):
        raise Exception(
            get_expected_vs_received_error_message(
                message=Errors.ID_TOKEN_MISSING_KEYS,
                expected=",".join(required_keys),
                received=",".join(present_keys),
            )
        )

    if id_token_payload["iss"] != issuer:
        raise Exception(
            get_expected_vs_received_error_message(
                message=Errors.ID_TOKEN_ISS_MISMATCH,
                expected=issuer,
                received=id_token_payload["iss"],
            )
        )

    if type(id_token_payload["iat"]) is not int:
        raise Exception(
            get_expected_vs_received_error_message(
                message=Errors.ID_TOKEN_IAT_INVALID,
                expected="a valid number",
                received=id_token_payload["iat"],
            )
        )

    if type(id_token_payload["exp"]) is not int:
        raise Exception(
            get_expected_vs_received_error_message(
                message=Errors.ID_TOKEN_EXP_INVALID,
                expected="a valid number",
                received=id_token_payload["exp"],
            )
        )

    curr_time = datetime.now()
    if id_token_payload["exp"] < curr_time.timestamp():
        raise Exception(
            get_expiry_error_message(
                message=Errors.ID_TOKEN_EXPIRED, expired_at=id_token_payload["exp"]
            )
        )

    if id_token_payload["aud"] != client_id:
        raise Exception(
            get_expected_vs_received_error_message(
                message=Errors.ID_TOKEN_AUD_MISMATCH,
                expected=client_id,
                received=id_token_payload["aud"],
            )
        )

    nonce_received = id_token_payload.get("nonce", None)
    if nonce is not None and nonce_received != nonce:
        raise Exception(
            get_expected_vs_received_error_message(
                message=Errors.ID_TOKEN_NONCE_MISMATCH,
                expected=nonce,
                received=nonce_received,
            )
        )

    if type(id_token_payload["sub"]) is not str or id_token_payload["sub"] == "":
        raise Exception(
            get_expected_vs_received_error_message(
                message=Errors.ID_TOKEN_SUB_INVALID,
                expected="a non-empty string",
                received=id_token_payload["sub"],
            )
        )
