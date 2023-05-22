from jwcrypto import jwk, jwe
from .error import Errors


def decrypt_data(encrypted_key: str, encrypted_data: dict, private_key: str):
    try:
        # Load private_key
        private_key_jwk = jwk.JWK.from_pem(private_key.encode("ascii"))
    except Exception as exc:
        raise Exception(Errors.PRIVATE_KEY_IMPORT) from exc

    try:
        jwe_key = jwe.JWE()
        # Decrypt encrypted_key to get block_key
        jwe_key.deserialize(encrypted_key, key=private_key_jwk)
    except Exception as exc:
        raise Exception(Errors.USERINFO_BLOCK_KEY_DECRYPT_FAILED) from exc

    block_key_json = jwe_key.payload
    try:
        # Load block_key
        block_key = jwk.JWK.from_json(block_key_json.decode("ascii").replace("'", '"'))
        jwe_data = jwe.JWE()

        # Initialise dict
        data_dict = {}

        for field in encrypted_data:
            # Decrypt encrypted_data[field] to get actual_data
            jwe_data.deserialize(encrypted_data[field], key=block_key)
            data_dict[field] = jwe_data.payload.decode("ascii")
    except Exception as exc:
        raise Exception(Errors.USERINFO_DATA_DECRYPT_FAILED) from exc

    return data_dict
