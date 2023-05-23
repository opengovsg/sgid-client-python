import json
import pytest
from requests import Request
import responses
from tests.mocks.constants import MOCK_CONSTANTS
from tests.mocks.helpers import (
    generate_encrypted_block_key,
    generate_user_info,
    get_client,
)


class TestUserInfo:
    def userinfo_callback(self, request: Request):
        auth_header: str = request.headers.get("authorization")
        if auth_header != f"Bearer {MOCK_CONSTANTS.data['access_token']}":
            return (401, {}, {})
        result = {
            "sub": MOCK_CONSTANTS.data["sub"],
            "key": generate_encrypted_block_key(),
            "data": generate_user_info(),
        }
        return (200, {}, json.dumps(result))

    @responses.activate
    def test_success_with_auth_header(self):
        # Arrange
        responses.add_callback(
            responses.GET,
            MOCK_CONSTANTS.server["userinfo_endpoint"],
            callback=self.userinfo_callback,
            content_type="application/json",
        )
        client = get_client()

        # Act
        sub, data = client.userinfo(
            sub=MOCK_CONSTANTS.data["sub"],
            access_token=MOCK_CONSTANTS.data["access_token"],
        )

        # Assert
        assert sub == MOCK_CONSTANTS.data["sub"]
        assert data == MOCK_CONSTANTS.data["userinfo"]

    @responses.activate
    def test_userinfo_endpoint_failure_no_res_headers(self):
        # Arrange
        response_json = {"message": "Your request is invalid"}
        responses.get(
            url=MOCK_CONSTANTS.server["userinfo_endpoint"],
            json=response_json,
            status=400,
        )
        client = get_client()

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"sgID responded with an error at the userinfo endpoint\nResponse status: 400\nResponse body: {json.dumps(response_json)}",
        ):
            sub, data = client.userinfo(
                sub=MOCK_CONSTANTS.data["sub"],
                access_token=MOCK_CONSTANTS.data["access_token"],
            )

    @responses.activate
    def test_userinfo_endpoint_failure_www_auth_header_error_prefix(self):
        # Arrange
        response_json = {"message": "Your request is invalid"}
        www_auth_message = "Your request failed"
        responses.get(
            url=MOCK_CONSTANTS.server["userinfo_endpoint"],
            json=response_json,
            headers={"www-authenticate": f"error={www_auth_message}"},
            status=400,
        )
        client = get_client()

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"sgID responded with an error at the userinfo endpoint\nResponse status: 400\nError message: {www_auth_message}",
        ):
            sub, data = client.userinfo(
                sub=MOCK_CONSTANTS.data["sub"],
                access_token=MOCK_CONSTANTS.data["access_token"],
            )

    @responses.activate
    def test_userinfo_endpoint_failure_www_auth_header_no_prefix(self):
        # Arrange
        response_json = {"message": "Your request is invalid"}
        www_auth_message = "Your request failed"
        responses.get(
            url=MOCK_CONSTANTS.server["userinfo_endpoint"],
            json=response_json,
            headers={"www-authenticate": www_auth_message},
            status=400,
        )
        client = get_client()

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"sgID responded with an error at the userinfo endpoint\nResponse status: 400\nError message: {www_auth_message}",
        ):
            sub, data = client.userinfo(
                sub=MOCK_CONSTANTS.data["sub"],
                access_token=MOCK_CONSTANTS.data["access_token"],
            )

    @responses.activate
    def test_userinfo_sub_mismatch(self):
        # Arrange
        responses.add_callback(
            responses.GET,
            MOCK_CONSTANTS.server["userinfo_endpoint"],
            callback=self.userinfo_callback,
            content_type="application/json",
        )
        sub_passed_to_userinfo = "someOtherSub"
        client = get_client()

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"Sub returned by sgID did not match the sub passed to the userinfo method. Check that you passed the correct sub to the userinfo method.",
        ):
            sub, data = client.userinfo(
                sub=sub_passed_to_userinfo,
                access_token=MOCK_CONSTANTS.data["access_token"],
            )

    @responses.activate
    def test_userinfo_block_key_decrypt_error(self):
        # Arrange
        responses.get(
            url=MOCK_CONSTANTS.server["userinfo_endpoint"],
            json={
                "sub": MOCK_CONSTANTS.data["sub"],
                "key": "invalidKey",
                "data": generate_user_info(),
            },
        )
        client = get_client()

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"Decryption of block key failed. Check that you passed the correct private key to the SgidClient constructor.",
        ):
            sub, data = client.userinfo(
                sub=MOCK_CONSTANTS.data["sub"],
                access_token=MOCK_CONSTANTS.data["access_token"],
            )

    @responses.activate
    def test_userinfo_data_decrypt_error(self):
        # Arrange
        responses.get(
            url=MOCK_CONSTANTS.server["userinfo_endpoint"],
            json={
                "sub": MOCK_CONSTANTS.data["sub"],
                "key": generate_encrypted_block_key(),
                "data": {"abc": "def"},
            },
        )
        client = get_client()

        # Act + Assert
        with pytest.raises(
            Exception,
            match=f"Decryption of data failed. Check that you passed the correct private key to the SgidClient constructor.",
        ):
            sub, data = client.userinfo(
                sub=MOCK_CONSTANTS.data["sub"],
                access_token=MOCK_CONSTANTS.data["access_token"],
            )
