import pytest
from flask import Flask, jsonify
from flycatch_auth import Auth, AuthCoreJwtConfig


class MockUserService:
    def load_user(self, username: str):
        return {
            "id": "1",
            "username": "testuser",
            "password": "password123",
            "grants": ["read_user"],
        }


print("credential_checker.......")


@pytest.fixture
def app():
    app = Flask(__name__)
    app.config["TESTING"] = True

    auth = Auth(
        user_service=MockUserService(),
        credential_checker=lambda input, user: input == user,
        jwt=AuthCoreJwtConfig(
            enable=True,
            secret="test-secret",
            expiresIn="1h",
            refresh=True,
            prefix="/auth/jwt",
        ),
    )

    auth.init_app(app)

    @app.route("/auth/jwt/login", methods=["POST"])
    def login():
        return auth.login("testuser", "password123")

    @app.route("/protected")
    @auth.verify()
    def protected():
        return jsonify({"message": "Access granted"}), 200

    return app


@pytest.fixture
def client(app):
    return app.test_client()


def test_jwt_token_generation(client):
    response = client.post("/auth/jwt/login")
    print(response.json)
    assert response.status_code == 200
    assert "access_token" in response.json


def test_protected_route_access(client):
    login_response = client.post("/auth/jwt/login")
    token = login_response.json["access_token"]

    response = client.get(
        "/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json["message"] == "Access granted"
