from typing import NamedTuple
from .error import Errors
import secrets
from base64 import urlsafe_b64encode
import hashlib


class GeneratePkcePairReturn(NamedTuple):
    code_verifier: str
    code_challenge: str


def generate_code_verifier(length=43) -> str:
    """Generates the random code verifier.

    Args:
        length (int, optional): The length of the code verifier to generate.
        Defaults to 43.

    Raises:
        Exception: if length is <43 or >128.

    Returns:
        str: The generated code verifier.
    """
    if length < 43 or length > 128:
        raise Exception(Errors.CODE_VERIFIER_LENGTH_ERROR)
    bytes = secrets.token_bytes(96)
    encoded = urlsafe_b64encode(bytes)
    return encoded.decode("ascii")[:length]


def generate_code_challenge(code_verifier: str) -> str:
    """Calculates the S256 code challenge for a provided code verifier.

    Args:
        code_verifier (str): The code verifier.

    Returns:
        str: The calculated code challenge.
    """
    verifier_bytearray = bytearray(code_verifier, encoding="ascii")
    code_challenge_hash = hashlib.sha256(verifier_bytearray).digest()
    with_padding = urlsafe_b64encode(code_challenge_hash).decode("ascii")
    # Slice off padding characters as they are not valid for code challenge
    # or verifier. This does not affect the validity of the code challenge
    return with_padding.replace("=", "")


def generate_pkce_pair(length=43) -> GeneratePkcePairReturn:
    """Generates a challenge pair where `code_challenge`
    is the generated S256 hash from `code_verifier`.

    Args:
        length (int, optional): The length of the code verifier. Defaults to 43.

    Raises:
        Exception: if length is <43 or >128.

    Returns:
        GeneratePkcePairReturn: Code challenge and code verifier.
    """
    if length < 43 or length > 128:
        raise Exception(Errors.PKCE_PAIR_LENGTH_ERROR)
    verifier = generate_code_verifier(length)
    challenge = generate_code_challenge(verifier)
    return GeneratePkcePairReturn(code_verifier=verifier, code_challenge=challenge)
