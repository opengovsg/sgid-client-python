from flask import (
    Flask,
    send_from_directory,
    request,
    make_response,
    redirect,
    abort,
)
import os
from fetch_static import fetch_static
from sgid_client import SgidClient
from dotenv import load_dotenv
from uuid import uuid4
from urllib.parse import urlencode, parse_qs
import webbrowser

load_dotenv()

fetch_static.fetch_static_files()

# In-memory store for user session data
# In a real application, this would be a database.
session_data = {}
SESSION_COOKIE_NAME = "exampleAppSession"

app = Flask(__name__)
sgid_client = SgidClient(
    client_id=os.getenv("SGID_CLIENT_ID"),
    client_secret=os.getenv("SGID_CLIENT_SECRET"),
    private_key=os.getenv("SGID_PRIVATE_KEY"),
    redirect_uri="http://localhost:2000/api/callback",
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
    auth_url_and_nonce = sgid_client.authorization_url(state=state)
    session_data[session_id] = {
        "state": state,
        "nonce": auth_url_and_nonce["nonce"],
    }
    res = make_response({"url": auth_url_and_nonce["url"]})
    res.set_cookie(SESSION_COOKIE_NAME, session_id, httponly=True)
    return res


@app.route("/api/callback")
def callback():
    auth_code = request.args.get("code")
    state = request.args.get("state")
    session_id = request.cookies.get(SESSION_COOKIE_NAME)

    session = session_data.get(session_id, None)
    # Validate that the state matches what we passed to sgID for this session
    if session is None or session["state"] != state:
        return redirect("/error")

    sub_and_access_token = sgid_client.callback(code=auth_code, nonce=session["nonce"])
    session["access_token"] = sub_and_access_token["access_token"]
    session["sub"] = sub_and_access_token["sub"]
    session_data[session_id] = session

    return redirect("/logged-in")


@app.route("/api/userinfo")
def userinfo():
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    session = session_data.get(session_id, None)
    access_token = None if session is None else session["access_token"]
    if session is None or access_token is None:
        abort(401)
    userinfo = sgid_client.userinfo(sub=session["sub"], access_token=access_token)

    # Add ice cream flavour to userinfo
    ice_cream_selection = parse_qs(session["state"])["icecream"][0]
    userinfo["data"]["iceCream"] = ice_cream_selection

    return userinfo


@app.route("/api/logout")
def logout():
    res = make_response({})
    res.delete_cookie(SESSION_COOKIE_NAME)
    return res


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve(path):
    if path != "" and os.path.exists(app.static_folder + "/" + path):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, "index.html")


webbrowser.open("http://localhost:2000")
