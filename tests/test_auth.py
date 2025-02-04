import pytest
from auth_package.auth import AuthCoreJwtConfig
from auth_package.flask_auth import FlaskAuth
from flask import Flask, jsonify

@pytest.fixture
def app():
    app = Flask(__name__)
    app.config["TESTING"] = True

    auth = FlaskAuth()
    auth.init_app(
        app,
        user_service=MockUserService(),
        credential_checker=lambda input, user: input == user["password"],
        jwt=AuthCoreJwtConfig(
            enable=True,
            secret="test-secret",
            expiresIn="1h",
            refresh=True,
            prefix="/auth/jwt",
        ),
    )

    @app.route("/protected")
    @auth.verify()
    @auth.has_grants(["read_user"])
    def protected():
        return jsonify({"message": "Access granted"}), 200

    return app

@pytest.fixture
def client(app):
    return app.test_client()

class MockUserService:
    def load_user(self, username: str):
        return {
            "id": "1",
            "username": "testuser",
            "password": "password123",
            "grants": ["read_user"],
        }

def test_jwt_token_generation(client):
    response = client.post("/auth/jwt/login", json={"username": "testuser", "password": "password123"})
    assert response.status_code == 200
    assert "access_token" in response.json

def test_protected_route_access(client):
    login_response = client.post("/auth/jwt/login", json={"username": "testuser", "password": "password123"})
    token = login_response.json["access_token"]

    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json["message"] == "Access granted"

def test_protected_route_without_token(client):
    response = client.get("/protected")
    assert response.status_code == 401
