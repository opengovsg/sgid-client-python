from typing import TypedDict
from .error import Errors
import secrets
from base64 import urlsafe_b64encode
import hashlib


class GeneratePkcePairReturn(TypedDict):
    code_verifier: str
    code_challenge: str


def generate_code_verifier(length=43) -> str:
    if length < 43 or length > 128:
        raise Exception(Errors["CODE_VERIFIER_LENGTH_ERROR"])
    bytes = secrets.token_bytes(96)
    encoded = urlsafe_b64encode(bytes)
    return encoded.decode("utf-8")[:length]


def generate_code_challenge(code_verifier: str) -> str:
    verifier_bytearray = bytearray(code_verifier, encoding="utf-8")
    code_challenge_hash = hashlib.sha256(verifier_bytearray).digest()
    with_padding = urlsafe_b64encode(code_challenge_hash).decode("utf-8")
    # Slice off padding characters as they are not valid for code challenge
    # or verifier. This does not affect the validity of the code challenge
    return with_padding.replace("=", "")


def generate_pkce_pair(length=43) -> GeneratePkcePairReturn:
    if length < 43 or length > 128:
        raise Exception(Errors["PKCE_PAIR_LENGTH_ERROR"])
    verifier = generate_code_verifier(length)
    challenge = generate_code_challenge(verifier)
    return {"code_verifier": verifier, "code_challenge": challenge}
