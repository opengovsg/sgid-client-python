import json
import re
import pytest
import responses
from datetime import datetime
import math
from .mocks.constants import MOCK_CONSTANTS
from .mocks.helpers import (
    create_id_token,
    make_base64url_json,
    get_client,
    get_jwks_response,
)


class TestCallback:
    @responses.activate
    def test_success_no_nonce(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        responses.post(
            url=MOCK_CONSTANTS.server["token_endpoint"],
            json={
                "id_token": create_id_token(),
                "access_token": MOCK_CONSTANTS.data["access_token"],
            },
        )

        # Act
        sub, access_token = client.callback(
            code=MOCK_CONSTANTS.data["auth_code"],
            code_verifier=MOCK_CONSTANTS.data["code_verifier"],
        )

        # Assert
        assert sub == MOCK_CONSTANTS.data["sub"]
        assert access_token == MOCK_CONSTANTS.data["access_token"]

    @responses.activate
    def test_success_with_nonce(self):
        # Arrange
        client = get_client()
        nonce = "mockNonce"
        responses.add(get_jwks_response())
        responses.post(
            url=MOCK_CONSTANTS.server["token_endpoint"],
            json={
                "id_token": create_id_token(nonce=nonce),
                "access_token": MOCK_CONSTANTS.data["access_token"],
            },
        )

        # Act
        sub, access_token = client.callback(
            code=MOCK_CONSTANTS.data["auth_code"],
            code_verifier=MOCK_CONSTANTS.data["code_verifier"],
            nonce=nonce,
        )

        # Assert
        assert sub == MOCK_CONSTANTS.data["sub"]
        assert access_token == MOCK_CONSTANTS.data["access_token"]

    @responses.activate
    def test_success_refetch_jwks(self):
        # Arrange
        client = get_client()
        # First return a non-working public key from jwks, then a working one
        # SgidClient should refetch the public key when the non-working one fails
        responses.add(
            get_jwks_response(json=MOCK_CONSTANTS.server["public_jwks_alternate"])
        )
        responses.add(get_jwks_response())
        responses.post(
            url=MOCK_CONSTANTS.server["token_endpoint"],
            json={
                "id_token": create_id_token(),
                "access_token": MOCK_CONSTANTS.data["access_token"],
            },
        )

        # Act
        sub, access_token = client.callback(
            code=MOCK_CONSTANTS.data["auth_code"],
            code_verifier=MOCK_CONSTANTS.data["code_verifier"],
        )

        # Assert
        assert len(responses.calls) == 3  # 1 to token, 2 to jwks
        assert responses.calls[0].request.url == MOCK_CONSTANTS.server["token_endpoint"]
        # call to get jwks for which signature validation fails
        assert responses.calls[1].request.url == MOCK_CONSTANTS.server["jwks_endpoint"]
        # call to get updated jwks
        assert responses.calls[2].request.url == MOCK_CONSTANTS.server["jwks_endpoint"]
        assert sub == MOCK_CONSTANTS.data["sub"]
        assert access_token == MOCK_CONSTANTS.data["access_token"]

    @responses.activate
    def test_token_endpoint_failure(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        response_json = {"message": "Your request is invalid"}
        responses.post(
            url=MOCK_CONSTANTS.server["token_endpoint"],
            json=response_json,
            status=400,
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"sgID responded with an error at the token endpoint\nResponse status: 400\nResponse body: {json.dumps(response_json)}",
        ):
            sub, access_token = client.callback(
                code=MOCK_CONSTANTS.data["auth_code"],
                code_verifier=MOCK_CONSTANTS.data["code_verifier"],
            )

    @responses.activate
    def test_malformed_id_token(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        responses.post(
            url=MOCK_CONSTANTS.server["token_endpoint"],
            json={
                "id_token": "abc.def",
                "access_token": MOCK_CONSTANTS.data["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=re.escape(
                "sgID server returned a malformed ID token which did not contain the expected components (header, payload, signature)"
            ),
        ):
            sub, access_token = client.callback(
                code=MOCK_CONSTANTS.data["auth_code"],
                code_verifier=MOCK_CONSTANTS.data["code_verifier"],
            )

    @responses.activate
    def test_malformed_id_token_header(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        responses.post(
            url=MOCK_CONSTANTS.server["token_endpoint"],
            json={
                "id_token": f"abc.{make_base64url_json({'a': 1})}.ghi",
                "access_token": MOCK_CONSTANTS.data["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match="ID token header or payload was malformed",
        ):
            sub, access_token = client.callback(
                code=MOCK_CONSTANTS.data["auth_code"],
                code_verifier=MOCK_CONSTANTS.data["code_verifier"],
            )

    @responses.activate
    def test_malformed_id_token_payload(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        responses.post(
            url=MOCK_CONSTANTS.server["token_endpoint"],
            json={
                "id_token": f"{make_base64url_json({'a': 1})}.def.ghi",
                "access_token": MOCK_CONSTANTS.data["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match="ID token header or payload was malformed",
        ):
            sub, access_token = client.callback(
                code=MOCK_CONSTANTS.data["auth_code"],
                code_verifier=MOCK_CONSTANTS.data["code_verifier"],
            )

    @responses.activate
    def test_id_token_wrong_signing_alg(self):
        # Arrange
        client = get_client()
        invalid_alg = "HS256"
        responses.add(get_jwks_response())
        responses.post(
            url=MOCK_CONSTANTS.server["token_endpoint"],
            json={
                "id_token": f"{make_base64url_json({'alg': invalid_alg})}.{make_base64url_json({'a': 1})}.ghi",
                "access_token": MOCK_CONSTANTS.data["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"Unexpected signing algorithm used for ID token. Expected RS256, received {invalid_alg}.",
        ):
            sub, access_token = client.callback(
                code=MOCK_CONSTANTS.data["auth_code"],
                code_verifier=MOCK_CONSTANTS.data["code_verifier"],
            )

    @responses.activate
    def test_id_token_missing_keys(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        responses.post(
            url=MOCK_CONSTANTS.server["token_endpoint"],
            json={
                "id_token": create_id_token(delete_keys=["iss", "sub", "aud", "exp"]),
                "access_token": MOCK_CONSTANTS.data["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"ID token payload did not contain the required keys. Expected iss,sub,aud,exp,iat, received iat.",
        ):
            sub, access_token = client.callback(
                code=MOCK_CONSTANTS.data["auth_code"],
                code_verifier=MOCK_CONSTANTS.data["code_verifier"],
            )

    @responses.activate
    def test_id_token_wrong_iss(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        invalid_iss = "invalid"
        responses.post(
            url=MOCK_CONSTANTS.server["token_endpoint"],
            json={
                "id_token": create_id_token(iss=invalid_iss),
                "access_token": MOCK_CONSTANTS.data["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"ID token 'iss' did not match expected value. Expected {MOCK_CONSTANTS.server['hostname'] + '/v2'}, received {invalid_iss}",
        ):
            sub, access_token = client.callback(
                code=MOCK_CONSTANTS.data["auth_code"],
                code_verifier=MOCK_CONSTANTS.data["code_verifier"],
            )

    @responses.activate
    def test_id_token_iat_invalid(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        invalid_iat = "invalid"
        responses.post(
            url=MOCK_CONSTANTS.server["token_endpoint"],
            json={
                "id_token": create_id_token(iat=invalid_iat),
                "access_token": MOCK_CONSTANTS.data["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"ID token 'iat' is invalid. Expected a valid number, received {invalid_iat}",
        ):
            sub, access_token = client.callback(
                code=MOCK_CONSTANTS.data["auth_code"],
                code_verifier=MOCK_CONSTANTS.data["code_verifier"],
            )

    @responses.activate
    def test_id_token_exp_invalid(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        invalid_exp = "invalid"
        responses.post(
            url=MOCK_CONSTANTS.server["token_endpoint"],
            json={
                "id_token": create_id_token(exp=invalid_exp),
                "access_token": MOCK_CONSTANTS.data["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"ID token 'exp' is invalid. Expected a valid number, received {invalid_exp}",
        ):
            sub, access_token = client.callback(
                code=MOCK_CONSTANTS.data["auth_code"],
                code_verifier=MOCK_CONSTANTS.data["code_verifier"],
            )

    @responses.activate
    def test_id_token_expired(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        five_min_ago = math.floor(datetime.now().timestamp() - 300)
        responses.post(
            url=MOCK_CONSTANTS.server["token_endpoint"],
            json={
                "id_token": create_id_token(exp=five_min_ago),
                "access_token": MOCK_CONSTANTS.data["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"ID token is expired. Current timestamp is \\d+/\\d+/\\d+, \\d+:\\d+:\\d+, expiry was at \\d+/\\d+/\\d+, \\d+:\\d+:\\d+",
        ):
            sub, access_token = client.callback(
                code=MOCK_CONSTANTS.data["auth_code"],
                code_verifier=MOCK_CONSTANTS.data["code_verifier"],
            )

    @responses.activate
    def test_id_token_invalid_aud(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        invalid_aud = "invalidAud"
        responses.post(
            url=MOCK_CONSTANTS.server["token_endpoint"],
            json={
                "id_token": create_id_token(aud=invalid_aud),
                "access_token": MOCK_CONSTANTS.data["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"ID token 'aud' did not match client ID. Expected {MOCK_CONSTANTS.client['client_id']}, received {invalid_aud}.",
        ):
            sub, access_token = client.callback(
                code=MOCK_CONSTANTS.data["auth_code"],
                code_verifier=MOCK_CONSTANTS.data["code_verifier"],
            )

    @responses.activate
    def test_id_token_invalid_nonce(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        nonce = "mockNonce"
        invalid_nonce = "invalidNonce"
        responses.post(
            url=MOCK_CONSTANTS.server["token_endpoint"],
            json={
                "id_token": create_id_token(nonce=nonce),
                "access_token": MOCK_CONSTANTS.data["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"ID token 'nonce' did not match the nonce passed to the callback function. Expected {invalid_nonce}, received {nonce}.",
        ):
            sub, access_token = client.callback(
                code=MOCK_CONSTANTS.data["auth_code"],
                code_verifier=MOCK_CONSTANTS.data["code_verifier"],
                nonce=invalid_nonce,
            )

    @responses.activate
    def test_id_token_invalid_sub(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        invalid_sub = 123
        responses.post(
            url=MOCK_CONSTANTS.server["token_endpoint"],
            json={
                "id_token": create_id_token(sub=invalid_sub),
                "access_token": MOCK_CONSTANTS.data["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"ID token 'sub' is invalid. Expected a non-empty string, received {invalid_sub}.",
        ):
            sub, access_token = client.callback(
                code=MOCK_CONSTANTS.data["auth_code"],
                code_verifier=MOCK_CONSTANTS.data["code_verifier"],
            )

    @responses.activate
    def test_id_token_empty_sub(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        responses.post(
            url=MOCK_CONSTANTS.server["token_endpoint"],
            json={
                "id_token": create_id_token(sub=""),
                "access_token": MOCK_CONSTANTS.data["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"ID token 'sub' is invalid. Expected a non-empty string, received .",
        ):
            sub, access_token = client.callback(
                code=MOCK_CONSTANTS.data["auth_code"],
                code_verifier=MOCK_CONSTANTS.data["code_verifier"],
            )

    @responses.activate
    def test_id_token_invalid_signature(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        responses.post(
            url=MOCK_CONSTANTS.server["token_endpoint"],
            json={
                # Pass in client's private key, which doesn't match server's public key
                "id_token": create_id_token(
                    private_key=MOCK_CONSTANTS.client["private_key"]
                ),
                "access_token": MOCK_CONSTANTS.data["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"ID token signature is invalid",
        ):
            sub, access_token = client.callback(
                code=MOCK_CONSTANTS.data["auth_code"],
                code_verifier=MOCK_CONSTANTS.data["code_verifier"],
            )

    @responses.activate
    def test_jwks_endpoint_failure(self):
        # Arrange
        client = get_client()
        response_json = {"message": "Your request is invalid"}
        responses.get(
            url=MOCK_CONSTANTS.server["jwks_endpoint"],
            json=response_json,
            status=400,
        )
        responses.post(
            url=MOCK_CONSTANTS.server["token_endpoint"],
            json={
                "id_token": create_id_token(),
                "access_token": MOCK_CONSTANTS.data["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"sgID responded with an error at the jwks endpoint\nResponse status: 400\nResponse body: {json.dumps(response_json)}",
        ):
            sub, access_token = client.callback(
                code=MOCK_CONSTANTS.data["auth_code"],
                code_verifier=MOCK_CONSTANTS.data["code_verifier"],
            )

    @responses.activate
    def test_access_token_invalid(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        responses.post(
            url=MOCK_CONSTANTS.server["token_endpoint"],
            json={
                # Pass in client's private key, which doesn't match server's public key
                "id_token": create_id_token(),
                "access_token": 123,
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"sgID token endpoint did not return a valid access token. Expected a non-empty string.",
        ):
            sub, access_token = client.callback(
                code=MOCK_CONSTANTS.data["auth_code"],
                code_verifier=MOCK_CONSTANTS.data["code_verifier"],
            )

    @responses.activate
    def test_access_token_empty(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        responses.post(
            url=MOCK_CONSTANTS.server["token_endpoint"],
            json={
                # Pass in client's private key, which doesn't match server's public key
                "id_token": create_id_token(),
                "access_token": "",
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"sgID token endpoint did not return a valid access token. Expected a non-empty string.",
        ):
            sub, access_token = client.callback(
                code=MOCK_CONSTANTS.data["auth_code"],
                code_verifier=MOCK_CONSTANTS.data["code_verifier"],
            )
