from flask import Flask, request, jsonify
from flycatch_auth import auth, AuthCoreJwtConfig, IdentityService, Identity

app = Flask(__name__)


class Userservice(IdentityService):
    def load_user(self, username: str) -> Identity:
        # user = user_db.get_users()
        return {
            "id": "1",
            "username": "testuser",
            "password": "password123",
            # read_user
            # "grants": [list(map(lambda user: user.permission.name, users))]
            "grants": ["read_user"]
        }


jwt_config = AuthCoreJwtConfig(
    enable=True,
    secret="mysecret",
    expiresIn="2h",
    refresh=True,
    prefix="/auth/jwt",
)

auth.init_app(
    app=app,
    user_service=Userservice(),
    credential_checker=lambda input, user: input == user,
    jwt=jwt_config,
)


@app.route("/me")
# @auth.verify()
def get_curr_user():
    return jsonify({"message": "Access granted"}), 200


if __name__ == "__main__":
    app.run(debug=True)
