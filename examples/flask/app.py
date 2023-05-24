from flask import (
    Flask,
    request,
    make_response,
    redirect,
    abort,
)
from flask_cors import CORS
import os
from sgid_client import SgidClient, generate_pkce_pair
from dotenv import load_dotenv
from uuid import uuid4
from urllib.parse import urlencode, parse_qs

load_dotenv()


# In-memory store for user session data
# In a real application, this would be a database.
session_data = {}
SESSION_COOKIE_NAME = "exampleAppSession"

app = Flask(__name__)
# Allow app to interact with demo frontend
frontend_host = os.getenv("SGID_FRONTEND_HOST") or "http://localhost:5173"
CORS(app, origins=[frontend_host], supports_credentials=True)

sgid_client = SgidClient(
    client_id=os.getenv("SGID_CLIENT_ID"),
    client_secret=os.getenv("SGID_CLIENT_SECRET"),
    private_key=os.getenv("SGID_PRIVATE_KEY"),
    redirect_uri="http://localhost:5001/api/redirect",
)


@app.route("/api/auth-url")
def get_auth_url():
    ice_cream_selection = request.args.get("icecream")
    session_id = str(uuid4())
    # Use search params to store state so other key-value pairs
    # can be added easily
    state = urlencode(
        {
            "icecream": ice_cream_selection,
        }
    )
    # We pass the user's ice cream preference as the state,
    # so after they log in, we can display it together with the
    # other user info.
    code_verifier, code_challenge = generate_pkce_pair()
    url, nonce = sgid_client.authorization_url(
        state=state, code_challenge=code_challenge
    )
    session_data[session_id] = {
        "state": state,
        "nonce": nonce,
        "code_verifier": code_verifier,
    }
    res = make_response({"url": url})
    res.set_cookie(SESSION_COOKIE_NAME, session_id, httponly=True)
    return res


@app.route("/api/redirect")
def callback():
    auth_code = request.args.get("code")
    state = request.args.get("state")
    session_id = request.cookies.get(SESSION_COOKIE_NAME)

    session = session_data.get(session_id, None)
    # Validate that the state matches what we passed to sgID for this session
    if session is None or session["state"] != state:
        return redirect(f"{frontend_host}/error")

    sub, access_token = sgid_client.callback(
        code=auth_code, code_verifier=session["code_verifier"], nonce=session["nonce"]
    )
    session["access_token"] = access_token
    session["sub"] = sub
    session_data[session_id] = session

    return redirect(f"{frontend_host}/logged-in")


@app.route("/api/userinfo")
def userinfo():
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    session = session_data.get(session_id, None)
    access_token = (
        None
        if session is None or "access_token" not in session
        else session["access_token"]
    )
    if session is None or access_token is None:
        abort(401)
    sub, data = sgid_client.userinfo(sub=session["sub"], access_token=access_token)

    # Add ice cream flavour to userinfo
    ice_cream_selection = parse_qs(session["state"])["icecream"][0]
    data["iceCream"] = ice_cream_selection

    return {"sub": sub, "data": data}


@app.route("/api/logout")
def logout():
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    del session_data[session_id]
    res = make_response({})
    res.delete_cookie(SESSION_COOKIE_NAME)
    return res
