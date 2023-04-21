from jwcrypto import jwk, jwe
from mocks.constants import MOCK_CONSTANTS
import json


def generateEncryptedBlockKey(blockKey, publicKey):
    rsaPublicKey = jwk.JWK.from_pem(publicKey.encode('utf-8'))
    jwe_data = jwe.JWE(plaintext=str(blockKey),
                       protected={'alg': 'RSA-OAEP-256', 'enc': 'A256GCM'},
                       recipient=rsaPublicKey)
    return jwe_data.serialize(compact=True)


def generateEncryptedMyInfo(blockKey, myInfo):
    current_key = jwk.JWK.from_json(
        json.dumps(blockKey))
    result = {}
    for (key, value) in myInfo.items():
        jwe_data = jwe.JWE(plaintext=str(value),
                           protected={'alg': 'A128GCMKW', 'enc': 'A128GCM'},
                           recipient=current_key)
        result[key] = jwe_data.serialize(compact=True)
    return result
