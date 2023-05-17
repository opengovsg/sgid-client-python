import json
import re
import pytest
from sgid_client.SgidClient import SgidClient
from urllib.parse import urlparse, parse_qs
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

DEFAULT_SCOPE = "openid myinfo.name"
DEFAULT_SGID_CODE_CHALLENGE_METHOD = "S256"
DEFAULT_RESPONSE_TYPE = "code"


class TestConstructor:
    def test_pkcs8(self):
        # Default args include PKCS8 private key
        client = get_client()
        assert type(client) is SgidClient

    def test_pkcs1(self):
        # Borrow server's PKCS1 private key to test that it imports correctly
        client = get_client(private_key=MOCK_CONSTANTS["server"]["private_key"])
        assert type(client) is SgidClient

    def test_hostname_default(self):
        client = get_client(delete_args=["hostname"])
        assert client.issuer == "https://api.id.gov.sg/v2"


class TestAuthorizationUrl:
    def test_state_codechallenge(self):
        # Arrange
        client = get_client()
        mock_state = "mockState"
        mock_code_challenge = "mockCodeChallenge"

        # Act
        url_and_nonce = client.authorization_url(
            state=mock_state, code_challenge=mock_code_challenge
        )
        url = urlparse(url_and_nonce["url"])
        query = parse_qs(url.query)

        # Assert
        assert (
            f"{url.scheme}://{url.hostname}{url.path}"
            == MOCK_CONSTANTS["server"]["auth_endpoint"]
        )
        # No repeated values
        for val in query.values():
            assert len(val) == 1
        assert query["client_id"][0] == MOCK_CONSTANTS["client"]["client_id"]
        assert query["scope"][0] == DEFAULT_SCOPE
        assert query["response_type"][0] == DEFAULT_RESPONSE_TYPE
        assert query["redirect_uri"][0] == MOCK_CONSTANTS["client"]["redirect_uri"]
        assert query["nonce"][0] == url_and_nonce["nonce"]
        assert query["state"][0] == mock_state
        assert query["code_challenge"][0] == mock_code_challenge
        assert query["code_challenge_method"][0] == DEFAULT_SGID_CODE_CHALLENGE_METHOD
        # No extra values
        assert len(query) == 8

    def test_state_codechallenge_scope_string(self):
        # Arrange
        client = get_client()
        mock_state = "mockState"
        mock_code_challenge = "mockCodeChallenge"
        mock_scope = "mockScope"

        # Act
        url_and_nonce = client.authorization_url(
            state=mock_state, code_challenge=mock_code_challenge, scope=mock_scope
        )
        url = urlparse(url_and_nonce["url"])
        query = parse_qs(url.query)

        # Assert
        assert (
            f"{url.scheme}://{url.hostname}{url.path}"
            == MOCK_CONSTANTS["server"]["auth_endpoint"]
        )
        # No repeated values
        for val in query.values():
            assert len(val) == 1
        assert query["client_id"][0] == MOCK_CONSTANTS["client"]["client_id"]
        assert query["scope"][0] == mock_scope
        assert query["response_type"][0] == DEFAULT_RESPONSE_TYPE
        assert query["redirect_uri"][0] == MOCK_CONSTANTS["client"]["redirect_uri"]
        assert query["nonce"][0] == url_and_nonce["nonce"]
        assert query["state"][0] == mock_state
        assert query["code_challenge"][0] == mock_code_challenge
        assert query["code_challenge_method"][0] == DEFAULT_SGID_CODE_CHALLENGE_METHOD
        # No extra values
        assert len(query) == 8

    def test_state_codechallenge_scope_stringarr(self):
        # Arrange
        client = get_client()
        mock_state = "mockState"
        mock_code_challenge = "mockCodeChallenge"
        mock_scope = ["scope1", "scope2", "scope3"]

        # Act
        url_and_nonce = client.authorization_url(
            state=mock_state, code_challenge=mock_code_challenge, scope=mock_scope
        )
        url = urlparse(url_and_nonce["url"])
        query = parse_qs(url.query)

        # Assert
        assert (
            f"{url.scheme}://{url.hostname}{url.path}"
            == MOCK_CONSTANTS["server"]["auth_endpoint"]
        )
        # No repeated values
        for val in query.values():
            assert len(val) == 1
        assert query["client_id"][0] == MOCK_CONSTANTS["client"]["client_id"]
        assert query["scope"][0] == " ".join(mock_scope)
        assert query["response_type"][0] == DEFAULT_RESPONSE_TYPE
        assert query["redirect_uri"][0] == MOCK_CONSTANTS["client"]["redirect_uri"]
        assert query["nonce"][0] == url_and_nonce["nonce"]
        assert query["state"][0] == mock_state
        assert query["code_challenge"][0] == mock_code_challenge
        assert query["code_challenge_method"][0] == DEFAULT_SGID_CODE_CHALLENGE_METHOD
        # No extra values
        assert len(query) == 8

    def test_state_codechallenge_nonce(self):
        # Arrange
        client = get_client()
        mock_state = "mockState"
        mock_code_challenge = "mockCodeChallenge"
        mock_nonce = "mockNonce"

        # Act
        url_and_nonce = client.authorization_url(
            state=mock_state, code_challenge=mock_code_challenge, nonce=mock_nonce
        )
        url = urlparse(url_and_nonce["url"])
        query = parse_qs(url.query)

        # Assert
        assert (
            f"{url.scheme}://{url.hostname}{url.path}"
            == MOCK_CONSTANTS["server"]["auth_endpoint"]
        )
        # No repeated values
        for val in query.values():
            assert len(val) == 1
        assert query["client_id"][0] == MOCK_CONSTANTS["client"]["client_id"]
        assert query["scope"][0] == DEFAULT_SCOPE
        assert query["response_type"][0] == DEFAULT_RESPONSE_TYPE
        assert query["redirect_uri"][0] == MOCK_CONSTANTS["client"]["redirect_uri"]
        assert query["nonce"][0] == url_and_nonce["nonce"]
        assert url_and_nonce["nonce"] == mock_nonce
        assert query["state"][0] == mock_state
        assert query["code_challenge"][0] == mock_code_challenge
        assert query["code_challenge_method"][0] == DEFAULT_SGID_CODE_CHALLENGE_METHOD
        # No extra values
        assert len(query) == 8

    def test_state_codechallenge_nonce_null(self):
        # Arrange
        client = get_client()
        mock_state = "mockState"
        mock_code_challenge = "mockCodeChallenge"

        # Act
        url_and_nonce = client.authorization_url(
            state=mock_state, code_challenge=mock_code_challenge, nonce=None
        )
        url = urlparse(url_and_nonce["url"])
        query = parse_qs(url.query)

        # Assert
        assert (
            f"{url.scheme}://{url.hostname}{url.path}"
            == MOCK_CONSTANTS["server"]["auth_endpoint"]
        )
        # No repeated values
        for val in query.values():
            assert len(val) == 1
        assert query["client_id"][0] == MOCK_CONSTANTS["client"]["client_id"]
        assert query["scope"][0] == DEFAULT_SCOPE
        assert query["response_type"][0] == DEFAULT_RESPONSE_TYPE
        assert query["redirect_uri"][0] == MOCK_CONSTANTS["client"]["redirect_uri"]
        assert url_and_nonce["nonce"] is None
        assert query["state"][0] == mock_state
        assert query["code_challenge"][0] == mock_code_challenge
        assert query["code_challenge_method"][0] == DEFAULT_SGID_CODE_CHALLENGE_METHOD
        # No extra values
        assert len(query) == 7

    def test_state_codechallenge_redirecturi(self):
        # Arrange
        client = get_client()
        mock_state = "mockState"
        mock_code_challenge = "mockCodeChallenge"
        mock_redirect_uri = "mockRedirectUri"

        # Act
        url_and_nonce = client.authorization_url(
            state=mock_state,
            code_challenge=mock_code_challenge,
            redirect_uri=mock_redirect_uri,
        )
        url = urlparse(url_and_nonce["url"])
        query = parse_qs(url.query)

        # Assert
        assert (
            f"{url.scheme}://{url.hostname}{url.path}"
            == MOCK_CONSTANTS["server"]["auth_endpoint"]
        )
        # No repeated values
        for val in query.values():
            assert len(val) == 1
        assert query["client_id"][0] == MOCK_CONSTANTS["client"]["client_id"]
        assert query["scope"][0] == DEFAULT_SCOPE
        assert query["response_type"][0] == DEFAULT_RESPONSE_TYPE
        assert query["redirect_uri"][0] == mock_redirect_uri
        assert query["nonce"][0] == url_and_nonce["nonce"]
        assert query["state"][0] == mock_state
        assert query["code_challenge"][0] == mock_code_challenge
        assert query["code_challenge_method"][0] == DEFAULT_SGID_CODE_CHALLENGE_METHOD
        # No extra values
        assert len(query) == 8

    def test_no_redirecturi(self):
        # Arrange
        client = get_client(redirect_uri=None)
        mock_state = "mockState"
        mock_code_challenge = "mockCodeChallenge"

        # Act
        with pytest.raises(
            Exception,
            match="No redirect URI registered with this client. You must either specify a valid redirect URI in the SgidClient constructor, or pass it to the authorization_url and callback functions.",
        ):
            client.authorization_url(
                state=mock_state, code_challenge=mock_code_challenge
            )


class TestCallback:
    @responses.activate
    def test_success_no_nonce(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        responses.post(
            url=MOCK_CONSTANTS["server"]["token_endpoint"],
            json={
                "id_token": create_id_token(),
                "access_token": MOCK_CONSTANTS["data"]["access_token"],
            },
        )

        # Act
        sub_and_access_token = client.callback(
            code=MOCK_CONSTANTS["data"]["auth_code"],
            code_verifier=MOCK_CONSTANTS["data"]["code_verifier"],
        )

        # Assert
        assert sub_and_access_token["sub"] == MOCK_CONSTANTS["data"]["sub"]
        assert (
            sub_and_access_token["access_token"]
            == MOCK_CONSTANTS["data"]["access_token"]
        )

    @responses.activate
    def test_success_with_nonce(self):
        # Arrange
        client = get_client()
        nonce = "mockNonce"
        responses.add(get_jwks_response())
        responses.post(
            url=MOCK_CONSTANTS["server"]["token_endpoint"],
            json={
                "id_token": create_id_token(nonce=nonce),
                "access_token": MOCK_CONSTANTS["data"]["access_token"],
            },
        )

        # Act
        sub_and_access_token = client.callback(
            code=MOCK_CONSTANTS["data"]["auth_code"],
            code_verifier=MOCK_CONSTANTS["data"]["code_verifier"],
            nonce=nonce,
        )

        # Assert
        assert sub_and_access_token["sub"] == MOCK_CONSTANTS["data"]["sub"]
        assert (
            sub_and_access_token["access_token"]
            == MOCK_CONSTANTS["data"]["access_token"]
        )

    @responses.activate
    def test_success_refetch_jwks(self):
        # Arrange
        client = get_client()
        # First return a non-working public key from jwks, then a working one
        # SgidClient should refetch the public key when the non-working one fails
        responses.add(
            get_jwks_response(json=MOCK_CONSTANTS["server"]["public_jwks_alternate"])
        )
        responses.add(get_jwks_response())
        responses.post(
            url=MOCK_CONSTANTS["server"]["token_endpoint"],
            json={
                "id_token": create_id_token(),
                "access_token": MOCK_CONSTANTS["data"]["access_token"],
            },
        )

        # Act
        sub_and_access_token = client.callback(
            code=MOCK_CONSTANTS["data"]["auth_code"],
            code_verifier=MOCK_CONSTANTS["data"]["code_verifier"],
        )

        # Assert
        assert sub_and_access_token["sub"] == MOCK_CONSTANTS["data"]["sub"]
        assert (
            sub_and_access_token["access_token"]
            == MOCK_CONSTANTS["data"]["access_token"]
        )

    @responses.activate
    def test_token_endpoint_failure(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        response_json = {"message": "Your request is invalid"}
        responses.post(
            url=MOCK_CONSTANTS["server"]["token_endpoint"],
            json=response_json,
            status=400,
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"sgID responded with an error at the token endpoint\nResponse status: 400\nResponse body: {json.dumps(response_json)}",
        ):
            sub_and_access_token = client.callback(
                code=MOCK_CONSTANTS["data"]["auth_code"],
                code_verifier=MOCK_CONSTANTS["data"]["code_verifier"],
            )

    @responses.activate
    def test_malformed_id_token(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        responses.post(
            url=MOCK_CONSTANTS["server"]["token_endpoint"],
            json={
                "id_token": "abc.def",
                "access_token": MOCK_CONSTANTS["data"]["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=re.escape(
                "sgID server returned a malformed ID token which did not contain the expected components (header, payload, signature)"
            ),
        ):
            sub_and_access_token = client.callback(
                code=MOCK_CONSTANTS["data"]["auth_code"],
                code_verifier=MOCK_CONSTANTS["data"]["code_verifier"],
            )

    @responses.activate
    def test_malformed_id_token_header(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        responses.post(
            url=MOCK_CONSTANTS["server"]["token_endpoint"],
            json={
                "id_token": f"abc.{make_base64url_json({'a': 1})}.ghi",
                "access_token": MOCK_CONSTANTS["data"]["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match="ID token header or payload was malformed",
        ):
            sub_and_access_token = client.callback(
                code=MOCK_CONSTANTS["data"]["auth_code"],
                code_verifier=MOCK_CONSTANTS["data"]["code_verifier"],
            )

    @responses.activate
    def test_malformed_id_token_payload(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        responses.post(
            url=MOCK_CONSTANTS["server"]["token_endpoint"],
            json={
                "id_token": f"{make_base64url_json({'a': 1})}.def.ghi",
                "access_token": MOCK_CONSTANTS["data"]["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match="ID token header or payload was malformed",
        ):
            sub_and_access_token = client.callback(
                code=MOCK_CONSTANTS["data"]["auth_code"],
                code_verifier=MOCK_CONSTANTS["data"]["code_verifier"],
            )

    @responses.activate
    def test_id_token_wrong_signing_alg(self):
        # Arrange
        client = get_client()
        invalid_alg = "HS256"
        responses.add(get_jwks_response())
        responses.post(
            url=MOCK_CONSTANTS["server"]["token_endpoint"],
            json={
                "id_token": f"{make_base64url_json({'alg': invalid_alg})}.{make_base64url_json({'a': 1})}.ghi",
                "access_token": MOCK_CONSTANTS["data"]["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"Unexpected signing algorithm used for ID token. Expected RS256, received {invalid_alg}.",
        ):
            sub_and_access_token = client.callback(
                code=MOCK_CONSTANTS["data"]["auth_code"],
                code_verifier=MOCK_CONSTANTS["data"]["code_verifier"],
            )

    @responses.activate
    def test_id_token_missing_keys(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        responses.post(
            url=MOCK_CONSTANTS["server"]["token_endpoint"],
            json={
                "id_token": create_id_token(delete_keys=["iss", "sub", "aud", "exp"]),
                "access_token": MOCK_CONSTANTS["data"]["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"ID token payload did not contain the required keys. Expected iss,sub,aud,exp,iat, received iat.",
        ):
            sub_and_access_token = client.callback(
                code=MOCK_CONSTANTS["data"]["auth_code"],
                code_verifier=MOCK_CONSTANTS["data"]["code_verifier"],
            )

    @responses.activate
    def test_id_token_wrong_iss(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        invalid_iss = "invalid"
        responses.post(
            url=MOCK_CONSTANTS["server"]["token_endpoint"],
            json={
                "id_token": create_id_token(iss=invalid_iss),
                "access_token": MOCK_CONSTANTS["data"]["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"ID token 'iss' did not match expected value. Expected {MOCK_CONSTANTS['server']['hostname'] + '/v2'}, received {invalid_iss}",
        ):
            sub_and_access_token = client.callback(
                code=MOCK_CONSTANTS["data"]["auth_code"],
                code_verifier=MOCK_CONSTANTS["data"]["code_verifier"],
            )

    @responses.activate
    def test_id_token_iat_invalid(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        invalid_iat = "invalid"
        responses.post(
            url=MOCK_CONSTANTS["server"]["token_endpoint"],
            json={
                "id_token": create_id_token(iat=invalid_iat),
                "access_token": MOCK_CONSTANTS["data"]["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"ID token 'iat' is invalid. Expected a valid number, received {invalid_iat}",
        ):
            sub_and_access_token = client.callback(
                code=MOCK_CONSTANTS["data"]["auth_code"],
                code_verifier=MOCK_CONSTANTS["data"]["code_verifier"],
            )

    @responses.activate
    def test_id_token_exp_invalid(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        invalid_exp = "invalid"
        responses.post(
            url=MOCK_CONSTANTS["server"]["token_endpoint"],
            json={
                "id_token": create_id_token(exp=invalid_exp),
                "access_token": MOCK_CONSTANTS["data"]["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"ID token 'exp' is invalid. Expected a valid number, received {invalid_exp}",
        ):
            sub_and_access_token = client.callback(
                code=MOCK_CONSTANTS["data"]["auth_code"],
                code_verifier=MOCK_CONSTANTS["data"]["code_verifier"],
            )

    @responses.activate
    def test_id_token_expired(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        five_min_ago = math.floor(datetime.now().timestamp() - 300)
        responses.post(
            url=MOCK_CONSTANTS["server"]["token_endpoint"],
            json={
                "id_token": create_id_token(exp=five_min_ago),
                "access_token": MOCK_CONSTANTS["data"]["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"ID token is expired. Current timestamp is \\d+/\\d+/\\d+, \\d+:\\d+:\\d+, expiry was at \\d+/\\d+/\\d+, \\d+:\\d+:\\d+",
        ):
            sub_and_access_token = client.callback(
                code=MOCK_CONSTANTS["data"]["auth_code"],
                code_verifier=MOCK_CONSTANTS["data"]["code_verifier"],
            )

    @responses.activate
    def test_id_token_invalid_aud(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        invalid_aud = "invalidAud"
        responses.post(
            url=MOCK_CONSTANTS["server"]["token_endpoint"],
            json={
                "id_token": create_id_token(aud=invalid_aud),
                "access_token": MOCK_CONSTANTS["data"]["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"ID token 'aud' did not match client ID. Expected {MOCK_CONSTANTS['client']['client_id']}, received {invalid_aud}.",
        ):
            sub_and_access_token = client.callback(
                code=MOCK_CONSTANTS["data"]["auth_code"],
                code_verifier=MOCK_CONSTANTS["data"]["code_verifier"],
            )

    @responses.activate
    def test_id_token_invalid_nonce(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        nonce = "mockNonce"
        invalid_nonce = "invalidNonce"
        responses.post(
            url=MOCK_CONSTANTS["server"]["token_endpoint"],
            json={
                "id_token": create_id_token(nonce=nonce),
                "access_token": MOCK_CONSTANTS["data"]["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"ID token 'nonce' did not match the nonce passed to the callback function. Expected {invalid_nonce}, received {nonce}.",
        ):
            sub_and_access_token = client.callback(
                code=MOCK_CONSTANTS["data"]["auth_code"],
                code_verifier=MOCK_CONSTANTS["data"]["code_verifier"],
                nonce=invalid_nonce,
            )

    @responses.activate
    def test_id_token_invalid_sub(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        invalid_sub = 123
        responses.post(
            url=MOCK_CONSTANTS["server"]["token_endpoint"],
            json={
                "id_token": create_id_token(sub=invalid_sub),
                "access_token": MOCK_CONSTANTS["data"]["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"ID token 'sub' is invalid. Expected a non-empty string, received {invalid_sub}.",
        ):
            sub_and_access_token = client.callback(
                code=MOCK_CONSTANTS["data"]["auth_code"],
                code_verifier=MOCK_CONSTANTS["data"]["code_verifier"],
            )

    @responses.activate
    def test_id_token_empty_sub(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        responses.post(
            url=MOCK_CONSTANTS["server"]["token_endpoint"],
            json={
                "id_token": create_id_token(sub=""),
                "access_token": MOCK_CONSTANTS["data"]["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"ID token 'sub' is invalid. Expected a non-empty string, received .",
        ):
            sub_and_access_token = client.callback(
                code=MOCK_CONSTANTS["data"]["auth_code"],
                code_verifier=MOCK_CONSTANTS["data"]["code_verifier"],
            )

    @responses.activate
    def test_id_token_invalid_signature(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        responses.post(
            url=MOCK_CONSTANTS["server"]["token_endpoint"],
            json={
                # Pass in client's private key, which doesn't match server's public key
                "id_token": create_id_token(
                    private_key=MOCK_CONSTANTS["client"]["private_key"]
                ),
                "access_token": MOCK_CONSTANTS["data"]["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"ID token signature is invalid",
        ):
            sub_and_access_token = client.callback(
                code=MOCK_CONSTANTS["data"]["auth_code"],
                code_verifier=MOCK_CONSTANTS["data"]["code_verifier"],
            )

    @responses.activate
    def test_jwks_endpoint_failure(self):
        # Arrange
        client = get_client()
        response_json = {"message": "Your request is invalid"}
        responses.get(
            url=MOCK_CONSTANTS["server"]["jwks_endpoint"],
            json=response_json,
            status=400,
        )
        responses.post(
            url=MOCK_CONSTANTS["server"]["token_endpoint"],
            json={
                "id_token": create_id_token(),
                "access_token": MOCK_CONSTANTS["data"]["access_token"],
            },
        )

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"sgID responded with an error at the jwks endpoint\nResponse status: 400\nResponse body: {json.dumps(response_json)}",
        ):
            sub_and_access_token = client.callback(
                code=MOCK_CONSTANTS["data"]["auth_code"],
                code_verifier=MOCK_CONSTANTS["data"]["code_verifier"],
            )

    @responses.activate
    def test_access_token_invalid(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        responses.post(
            url=MOCK_CONSTANTS["server"]["token_endpoint"],
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
            sub_and_access_token = client.callback(
                code=MOCK_CONSTANTS["data"]["auth_code"],
                code_verifier=MOCK_CONSTANTS["data"]["code_verifier"],
            )

    @responses.activate
    def test_access_token_empty(self):
        # Arrange
        client = get_client()
        responses.add(get_jwks_response())
        responses.post(
            url=MOCK_CONSTANTS["server"]["token_endpoint"],
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
            sub_and_access_token = client.callback(
                code=MOCK_CONSTANTS["data"]["auth_code"],
                code_verifier=MOCK_CONSTANTS["data"]["code_verifier"],
            )
