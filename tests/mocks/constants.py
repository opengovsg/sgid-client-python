import json

mock_jwk = json.loads(open('./tests/mocks/mockClientKeys.json').read())
hostname = 'https://id.sgid.com'
api_version = 3

MOCK_CONSTANTS = {
    'CLIENT': {
        'CLIENT_ID': 'mockClientId',
        'CLIENT_SECRET': 'mockClientSecret',
        'REDIRECT_URI': 'https://sgid.com/callback',
        'PUBLIC_KEY': mock_jwk['publicKey'],
        'PRIVATE_KEY': mock_jwk['privateKey'],
    },
    'SERVER': {
        'HOSTNAME': hostname,
        'API_VERSION': str(api_version),
        'AUTHORIZATION_ENDPOINT': hostname + '/v' + str(api_version) + '/oauth/authorize',
        'TOKEN_ENDPOINT': hostname + '/v' + str(api_version) + '/oauth/token',
        'USERINFO_ENDPOINT': hostname + '/v' + str(api_version) + '/oauth/userinfo',
        'JWKS_ENDPOINT': hostname + '/.well-known/jwks.json',
    },
    'RESPONSE': {
        'BLOCK_KEY': {
            'kty': 'oct',
            'alg': 'A128GCM',
            'k': 'kMnXcwOisOQskMlIu5oqVA',
        },
        'SUB': 'mockSub',
        'AUTH_CODE': 'mockAuthCode',
        'ACCESS_TOKEN': 'mockAccessToken',
        'USERINFO': {
            'myKey': 'myValue'
        }
    }
}
