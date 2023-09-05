from Crypto.PublicKey import RSA
import json

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

def is_stringified_array_or_object(possible_array_or_object_string: str) -> bool:
    """Checks whether a string starts and ends with square brackets or starts and ends with curly brackets.

    Args:
        possible_array_or_object_string (str): A string that might or might not be a stringified array.

    Returns:
        bool: either true or false
    """
    return (possible_array_or_object_string[0] == '[' and possible_array_or_object_string[len(possible_array_or_object_string)-1] == ']') or (possible_array_or_object_string[0] == '[' and possible_array_or_object_string[len(possible_array_or_object_string)-1] == ']')

def safe_json_parse(json_string: str) -> dict | list | str:
    """Safely parses a stringified JSON object or array.

    Args:
        json_string (str): A stringified JSON object or array.

    Returns:
        dict | list | str: The parsed JSON object or array, or the original string if parsing fails.
    """
    try:
        return json.loads(json_string)
    except Exception:
        return json_string