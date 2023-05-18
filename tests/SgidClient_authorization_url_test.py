import pytest
from urllib.parse import urlparse, parse_qs
from .mocks.constants import MOCK_CONSTANTS
from .mocks.helpers import (
    get_client,
)

DEFAULT_SCOPE = "openid myinfo.name"
DEFAULT_SGID_CODE_CHALLENGE_METHOD = "S256"
DEFAULT_RESPONSE_TYPE = "code"


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