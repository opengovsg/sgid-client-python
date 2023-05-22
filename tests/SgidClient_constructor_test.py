import pytest
from sgid_client.SgidClient import SgidClient
from tests.mocks.constants import MOCK_CONSTANTS
from tests.mocks.helpers import get_client


class TestConstructor:
    def test_pkcs8(self):
        # Default args include PKCS8 private key
        client = get_client()
        assert type(client) is SgidClient

    def test_pkcs1(self):
        # Borrow server's PKCS1 private key to test that it imports correctly
        client = get_client(private_key=MOCK_CONSTANTS.server["private_key"])
        assert type(client) is SgidClient

    def test_hostname_default(self):
        client = get_client(delete_args=["hostname"])
        assert client.issuer == "https://api.id.gov.sg/v2"

    def test_private_key_error(self):
        with pytest.raises(
            Exception,
            match="Failed to import private key. Check that privateKey is a valid PKCS1 or PKCS8 key.",
        ):
            client = get_client(private_key="invalid_key")
