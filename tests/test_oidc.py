from sgidclient.oidc import SgidClient
from mocks.constants import MOCK_CONSTANTS
from mocks import helpers
import responses

sgidClient = SgidClient(
    client_id=MOCK_CONSTANTS['CLIENT']['CLIENT_ID'],
    client_secret=MOCK_CONSTANTS['CLIENT']['CLIENT_SECRET'],
    redirect_uri=MOCK_CONSTANTS['CLIENT']['REDIRECT_URI'],
    private_key=MOCK_CONSTANTS['CLIENT']['PRIVATE_KEY'],
    api_version=3,
    hostname='https://id.sgid.com'
)


def test_sgid_exist():
    assert sgidClient != None


def test_sgid_autorization_url():
    url = sgidClient.authorization_url('dev')
    assert url.startswith(MOCK_CONSTANTS['SERVER']['AUTHORIZATION_ENDPOINT'])
    assert url.__contains__('state=dev')
    assert url.__contains__('response_type=code')
    assert url.__contains__('client_id='+MOCK_CONSTANTS['CLIENT']['CLIENT_ID'])
    assert url.__contains__('redirect_uri=')
    assert url.__contains__('scope=')
    assert url.__contains__('nonce=')


@responses.activate
def test_sgid_callback():
    responses.add(
        responses.POST,
        MOCK_CONSTANTS['SERVER']['HOSTNAME']+'/v3/oauth/token',
        json={"access_token": MOCK_CONSTANTS['RESPONSE']['ACCESS_TOKEN']},
        status=200)
    response = sgidClient.callback(
        code=MOCK_CONSTANTS['RESPONSE']['AUTH_CODE'])
    assert response['access_token'] == MOCK_CONSTANTS['RESPONSE']['ACCESS_TOKEN']


@responses.activate
def test_sgid_userinfo():
    responses.add(
        responses.GET,
        MOCK_CONSTANTS['SERVER']['HOSTNAME']+'/v3/oauth/userinfo',
        json={
            "sub": MOCK_CONSTANTS['RESPONSE']['SUB'],
            "key": helpers.generateEncryptedBlockKey(MOCK_CONSTANTS['RESPONSE']['BLOCK_KEY'], MOCK_CONSTANTS['CLIENT']['PUBLIC_KEY']),
            "data": helpers.generateEncryptedMyInfo(MOCK_CONSTANTS['RESPONSE']['BLOCK_KEY'], MOCK_CONSTANTS['RESPONSE']['USERINFO'])
        },
        status=200)
    response = sgidClient.userinfo(
        access_token=MOCK_CONSTANTS['RESPONSE']['ACCESS_TOKEN'])
    assert response['sub'] == MOCK_CONSTANTS['RESPONSE']['SUB']
    assert response['data'] == MOCK_CONSTANTS['RESPONSE']['USERINFO']
