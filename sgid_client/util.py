from Crypto.PublicKey import RSA

from sgid_client.error import Errors


def convert_to_pkcs8(private_key: str) -> str:
    """Converts a private key in PKCS1 format to PKCS8.

    Args:
        private_key (str): Private key as a string.

    Raises:
        Exception: if private key is invalid.

    Returns:
        str: Private key in PKCS8 format.
    """
    try:
        imported = RSA.import_key(extern_key=private_key)
        return imported.export_key(pkcs=8).decode("ascii")
    except Exception as exc:
        raise Exception(Errors.PRIVATE_KEY_IMPORT) from exc
