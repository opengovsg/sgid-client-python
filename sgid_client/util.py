from Crypto.PublicKey import RSA

from sgid_client.error import Errors


def convert_to_pkcs8(private_key: str) -> str:
    try:
        imported = RSA.import_key(extern_key=private_key)
        return imported.export_key(pkcs=8).decode("ascii")
    except Exception as exc:
        raise Exception(Errors["PRIVATE_KEY_IMPORT"]) from exc
