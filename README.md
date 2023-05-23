![](sgid-logo.png)

# sgid-client-python

The official Python client for sgID.

## Installation

```bash
pip install sgid-client
```

## Usage

For more detailed instructions on how to register your client and integrate with sgID, please refer to our [developer documentation](https://docs.id.gov.sg/).

### Initialization

```python
from sgid_client import SgidClient

sgid_client = SgidClient(
    client_id='<Insert your client ID>',
    client_secret='<Insert your client secret>',
    private_key='<Insert your private key as a string>',
    redirect_uri='<Insert your redirect URI>',
)
```

### Generate code challenge and verifier

This is a required step for OIDC ([more info](https://oauth.net/2/pkce/)).

- The `code_challenge` should be provided in `authorization_url`.
- The `code_verifier` should be stored in the user's session so it can be retrieved later for use in `callback`.
- A unique pair should be generated for each authorization request.

```python
generate_pkce_pair(length=43)
```

- Args:
  - `length` (`int`, optional): The length of the code verifier. Defaults to 43.
- Returns: `NamedTuple`
  - `code_verifier`: `str` Randomly generated string
  - `code_challenge`: `str` S256 hash of code verifier

Example usage:

```python
pkce_pair = generate_pkce_pair()
code_verifier = pkce_pair['code_verifier']
code_challenge = pkce_pair['code_challenge']
```

### Get authorization URL

```python
authorization_url(
    state: str,
    code_challenge: str,
    redirect_uri: str | None = None,
    scope: str | list[str] = "openid myinfo.name",
    nonce: str | None = secrets.token_urlsafe(32),
)
```

- Args:
  - `state` (`str`): A string which will be passed back to your application once
    the end-user logs in. You can also use this to track per-request state.
  - `code_challenge` (`str`): The code challenge generated from generate_pkce_pair()
  - `redirect_uri` (`str | None`, optional): The redirect URI used in the authorization
    request. If this param is provided, it will be used instead of the redirect
    URI provided in the SgidClient constructor. If not provided in the constructor,
    the redirect URI must be provided here.. Defaults to None.
  - `scope` (`str | list[str]`, optional): 'openid' must be provided as a
    scope. Defaults to `"openid myinfo.name"`.
  - `nonce` (`str | None`, optional): Unique nonce for this request. If this param is
    not provided, a nonce is generated and returned. To prevent this behaviour,
    specify None for this param. Defaults to `secrets.token_urlsafe(32)`.
- Returns: `NamedTuple`
  - `url`: `str` Generated authorization url.
  - `nonce`: `str | None` Provided nonce, randomly generated nonce, or `None` (based on nonce input).
    Should be stored in the user's session so it can be retrieved later for use in `callback`.

Example usage:

```python
auth_url_and_nonce = sgid_client.authorization_url(
    state="state", code_challenge=pkce_pair["code_challenge"]
)
```

### Token exchange

```python
callback(
    code: str,
    code_verifier: str,
    nonce: str | None = None,
    redirect_uri: str | None = None,
)
```

- Args:
  - `code` (`str`): The authorization code received from the authorization server
  - `code_verifier` (`str`): The code verifier corresponding to the code challenge
    that was passed to `authorization_url` for this request
  - `nonce` (`str | None`, optional): Nonce passed to `authorization_url` for this request.
    Specify None if no nonce was passed to `authorization_url`. Defaults to None.
  - `redirect_uri` (`str | None`, optional): The redirect URI used in the authorization
    request. If not specified, defaults to the one passed to the SgidClient constructor.
- Returns: `NamedTuple`
  - `sub`: `str` Represents a unique identifer for the end-user.
  - `access_token`: `str` Access token used to request user info.

Example usage:

```python
sub_and_access_token = sgid_client.callback(
    code=auth_code, code_verifier=session["code_verifier"], nonce=session["nonce"]
)
session["access_token"] = sub_and_access_token["access_token"]
session["sub"] = sub_and_access_token["sub"]
```

### User info

```python
userinfo(sub: str, access_token: str)
```

- Args:
  - `sub` (`str`): The sub returned from the callback function
  - `access_token` (`str`): The access token returned from the callback function
- Returns: `NamedTuple`
  - `sub`: `str` Represents a unique identifer for the end-user.
  - `data`: `dict` A dictionary containing end-user info where the keys are the scopes requested in `authorization_url`.

Example usage:

```python
userinfo = sgid_client.userinfo(
    sub=session["sub"], access_token=session["access_token"]
)
```

## Supported Runtime and Environment

Python >=3.11

## For contributors

### Running tests

To run the tests locally,

1. [Install Poetry](https://python-poetry.org/docs/#installation).
2. Run the following:

```bash
poetry run pytest
```
