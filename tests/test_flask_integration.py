import pytest
from flask import Flask, jsonify, request
from flycatch_auth import auth, AuthCoreJwtConfig, IdentityService, Identity


class MockUserService(IdentityService):
    def load_user(self, username: str) -> Identity:
        return {"id": "1", "username": "testuser", "password": "password123", "grants": ["read_user"]}


@pytest.fixture
def app():

    app = Flask(__name__)
    jwt_config = AuthCoreJwtConfig(
        enable=True,
        secret="mysecret",
        expiresIn="2h",
        refresh=True,
        prefix="/auth/jwt",
    )

    auth.init_app(
        app=app,
        user_service=MockUserService(),
        credential_checker=lambda input, user: input == user,
        jwt=jwt_config,
    )

    @app.route("/me")
    # @auth.verify()
    # @auth.has_grants(["read_user"])["flask"]
    def get_curr_user():
        return jsonify({"name": "Test User"}), 200
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def test_me_route_with_auth(client):
    login_response = client.post(
        "/auth/jwt/login", json={"username": "testuser", "password": "password123"})

    assert login_response.status_code == 200, "Login failed"

    token = login_response.json.get("access_token")
    assert token, "Token is missing from response"

    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/me", headers=headers)

    assert response.status_code == 200, "Access denied"
    assert response.json["name"] == "Test User"
