from flask import Flask, jsonify, request
import uuid
from flask_jwt_extended import (
    JWTManager,
    jwt_required,
    create_access_token,
    jwt_refresh_token_required,
    create_refresh_token,
    get_jwt_identity,
    set_access_cookies,
    set_refresh_cookies,
    unset_jwt_cookies,
)

EXPIRY_TIME = 3600
app = Flask(__name__)

# # Configure application to store JWTs in cookies
app.config["JWT_TOKEN_LOCATION"] = ["headers", "json"]

app.config["JWT_JSON_KEY"] = "access_token"
app.config["JWT_REFRESH_JSON_KEY"] = "refresh_token"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = EXPIRY_TIME
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = 18 * 3600

# Set the secret key to sign the JWTs with
app.config["JWT_SECRET_KEY"] = str(uuid.uuid4())

jwt = JWTManager(app)


@app.route("/api/accounts/prelogin", methods=["POST"])
def pre_login():
    return jsonify({"Kdf": 0, "KdfIterations": 100000,})


@app.route("/identity/connect/token", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    if username != "test" or password != "test":
        return jsonify({"login": False}), 401

    # Create the tokens we will be sending back to the user
    access_token = create_access_token(identity=username)
    refresh_token = create_refresh_token(identity=username)

    # Set the JWTs and the CSRF double submit protection cookies
    # in this response
    resp = jsonify(
        {
            "login": True,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": EXPIRY_TIME,
            "token_type": "Bearer",
        }
    )
    return resp, 200


@app.route("/api/example", methods=["GET"])
@jwt_required
def protected():
    username = get_jwt_identity()
    return jsonify({"hello": "from {}".format(username)}), 200


if __name__ == "__main__":
    app.run()
