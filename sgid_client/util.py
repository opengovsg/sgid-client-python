from Crypto.PublicKey import RSA


def convert_to_pkcs8(private_key: str) -> str:
    imported = RSA.import_key(extern_key=private_key)
    return imported.export_key(pkcs=8).decode("ascii")
