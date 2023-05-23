from typing import NamedTuple
from datetime import datetime

from requests import Response


class SgidClientError(NamedTuple):
    MISSING_REDIRECT_URI: str
    TOKEN_ENDPOINT_FAILED: str
    ID_TOKEN_MALFORMED: str
    ID_TOKEN_HEADER_PAYLOAD_MALFORMED: str
    ID_TOKEN_WRONG_SIGNING_ALG: str
    ID_TOKEN_MISSING_KEYS: str
    ID_TOKEN_ISS_MISMATCH: str
    ID_TOKEN_IAT_INVALID: str
    ID_TOKEN_EXP_INVALID: str
    ID_TOKEN_EXPIRED: str
    ID_TOKEN_AUD_MISMATCH: str
    ID_TOKEN_NONCE_MISMATCH: str
    ID_TOKEN_SUB_INVALID: str
    ID_TOKEN_SIGNATURE_INVALID: str
    ACCESS_TOKEN_INVALID: str
    USERINFO_ENDPOINT_FAILED: str
    JWKS_ENDPOINT_FAILED: str
    PRIVATE_KEY_IMPORT: str
    USERINFO_SUB_MISMATCH: str
    USERINFO_BLOCK_KEY_DECRYPT_FAILED: str
    USERINFO_DATA_DECRYPT_FAILED: str
    CODE_VERIFIER_LENGTH_ERROR: str
    PKCE_PAIR_LENGTH_ERROR: str


Errors = SgidClientError(
    MISSING_REDIRECT_URI="No redirect URI registered with this client. You must either specify a valid redirect URI in the SgidClient constructor, or pass it to the authorization_url and callback functions.",
    TOKEN_ENDPOINT_FAILED="sgID responded with an error at the token endpoint",
    ID_TOKEN_MALFORMED="sgID server returned a malformed ID token which did not contain the expected components (header, payload, signature)",
    ID_TOKEN_HEADER_PAYLOAD_MALFORMED="ID token header or payload was malformed",
    ID_TOKEN_WRONG_SIGNING_ALG="Unexpected signing algorithm used for ID token",
    ID_TOKEN_MISSING_KEYS="ID token payload did not contain the required keys",
    ID_TOKEN_ISS_MISMATCH="ID token 'iss' did not match expected value",
    ID_TOKEN_IAT_INVALID="ID token 'iat' is invalid",
    ID_TOKEN_EXP_INVALID="ID token 'exp' is invalid",
    ID_TOKEN_EXPIRED="ID token is expired",
    ID_TOKEN_AUD_MISMATCH="ID token 'aud' did not match client ID",
    ID_TOKEN_NONCE_MISMATCH="ID token 'nonce' did not match the nonce passed to the callback function",
    ID_TOKEN_SUB_INVALID="ID token 'sub' is invalid",
    ID_TOKEN_SIGNATURE_INVALID="ID token signature is invalid",
    ACCESS_TOKEN_INVALID="sgID token endpoint did not return a valid access token. Expected a non-empty string.",
    USERINFO_ENDPOINT_FAILED="sgID responded with an error at the userinfo endpoint",
    JWKS_ENDPOINT_FAILED="sgID responded with an error at the jwks endpoint",
    USERINFO_SUB_MISMATCH="Sub returned by sgID did not match the sub passed to the userinfo method. Check that you passed the correct sub to the userinfo method.",
    PRIVATE_KEY_IMPORT="Failed to import private key. Check that privateKey is a valid PKCS1 or PKCS8 key.",
    USERINFO_BLOCK_KEY_DECRYPT_FAILED="Decryption of block key failed. Check that you passed the correct private key to the SgidClient constructor.",
    USERINFO_DATA_DECRYPT_FAILED="Decryption of data failed. Check that you passed the correct private key to the SgidClient constructor.",
    CODE_VERIFIER_LENGTH_ERROR="Code verifier should have a minimum length of 43 and a maximum length of 128",
    PKCE_PAIR_LENGTH_ERROR="generate_pkce_pair should receive a minimum length of 43 and a maximum length of 128",
)


def get_network_error_message(message: str, status: int, body: str) -> str:
    return f"{message}\nResponse status: {status}\nResponse body: {body}"


def get_expected_vs_received_error_message(message: str, expected, received) -> str:
    return f"{message}. Expected {expected}, received {received}."


def get_expiry_error_message(message: str, expired_at: float) -> str:
    curr_time = datetime.now()
    return f"{message}. Current timestamp is {curr_time.strftime('%Y/%m/%d, %H:%M:%S')}, expiry was at {datetime.fromtimestamp(expired_at).strftime('%Y/%m/%d, %H:%M:%S')}"


def get_www_authenticate_error_message(message: str, res: Response) -> str:
    www_authenticate_header = res.headers.get("www-authenticate", None)
    if www_authenticate_header is None:
        return get_network_error_message(
            message=message, status=res.status_code, body=res.text
        )

    if www_authenticate_header.startswith("error="):
        return f"{message}\nResponse status: {res.status_code}\nError message: {www_authenticate_header[len('error='):]}"
    return f"{message}\nResponse status: {res.status_code}\nError message: {www_authenticate_header}"
