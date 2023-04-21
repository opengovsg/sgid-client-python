from authlib.integrations.requests_client import OAuth2Session
from jwcrypto import jwk, jwe
import secrets
import requests
import json


class SgidClient:
    """
    SgidClient is a class that allows you to interact with the sgID API.
    """

    def __init__(self, client_id: str, client_secret: str, private_key: str, redirect_uri: str, scope: str = 'openid myinfo.nric_number', hostname: str = 'https://api.id.gov.sg', api_version: int = 1):
        """Constructor for SgidClient class.

        :param client_id: The client ID of your application.
        :param client_secret: The client secret of your application.
        :param private_key: The private key of your application.
        :param redirect_uri: The redirect URI of your application.
        :param scope: The scope of your application.
        :param hostname: The hostname of the sgID API.
        :param api_version: The version of the sgID API.
        """
        client = OAuth2Session(client_id, client_secret, redirect_uri, scope)
        client.authorization_endpoint = hostname + \
            '/v'+str(api_version)+'/oauth/authorize'
        client.token_endpoint = hostname+'/v'+str(api_version)+'/oauth/token'
        client.userinfo_endpoint = hostname + \
            '/v'+str(api_version)+'/oauth/userinfo'
        client.redirect_uri = redirect_uri
        client.scope = scope.replace(' ', ' ')
        client.fetch_token
        client.client_id = client_id
        client.client_secret = client_secret

        self.private_key = private_key
        self.sgID = client
        self.base_url = hostname+'/v'+str(api_version)

    def authorization_url(self, state: str, nonce: str = secrets.token_urlsafe(16)) -> str:
        """This function returns the authorization url for the sgID login page

        :param state: state to be passed to the sgID login page
        :param nonce: nonce to be passed to the sgID login page
        :return: authorization url
        :rtype: `str`
        """
        authorization_url, state = self.sgID.create_authorization_url(
            self.sgID.authorization_endpoint, state)
        authorization_url = authorization_url + '&nonce=' + nonce
        return authorization_url

    def callback(self, code: str, nonce: str = None) -> dict:
        """This function returns the access token from the sgID API

        :param code: code returned from the sgID login page
        :param nonce: nonce used to generate the authorization url
        :return: access_token
        :rtype: `{access_token': str}`
        """

        response = requests.post(self.sgID.token_endpoint, {
            "code": code,
            "client_id": self.sgID.client_id,
            "client_secret": self.sgID.client_secret,
            "grant_type": "authorization_code",
            "redirect_uri": self.sgID.redirect_uri
        }).json()
        return {
            'access_token': response['access_token'],
        }

    def userinfo(self, access_token: str) -> dict:
        """This function returns the user info from the sgID API

        :param access_token: access token returned from .callback()
        :return: sub and data
        :rtype: `{'sub': str, 'data': dict}`
        """
        response = requests.get(self.sgID.userinfo_endpoint, headers={
                                "Authorization": "Bearer " + access_token}).json()
        output = {}
        output['sub'] = response['sub']
        output['data'] = self.decrypt_data(
            response['key'], response['data'], self.private_key)
        return output

    def decrypt_data(self, encrypted_key: str, encrypted_data: any, private_key_pem_string: str):
        # Load private_key
        private_key = jwk.JWK.from_pem(private_key_pem_string.encode('utf-8'))
        jwe_key = jwe.JWE()

        # Decrypt encrypted_key to get block_key
        jwe_key.deserialize(encrypted_key, key=private_key)
        block_key_json = jwe_key.payload

        # Load block_key
        block_key = jwk.JWK.from_json(
            block_key_json.decode('utf-8').replace('\'', '"'))
        jwe_data = jwe.JWE()
        print(block_key)

        # Initialise dict
        data_dict = {}

        for field in encrypted_data:
            # Decrypt encrypted_data[field] to get actual_data
            jwe_data.deserialize(encrypted_data[field], key=block_key)
            data_dict[field] = jwe_data.payload.decode('utf-8')

        return data_dict
