import pytest
from flask import Flask, request, jsonify
from flycatch_auth import Auth, AuthCoreJwtConfig


class MockUserService:
    def load_user(self, username: str):
        return {
            "id": "1",
            "username": "testuser",
            "password": "password123",
            "grants": ["read_user"],
        }


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
        username = request.json.get("username")
        password = request.json.get("password")
        user = auth.authenticate(username, password)
        if user:
            access_token = auth.jwt.generate_token(user)
            refresh_token = auth.jwt.generate_refresh_token(user)
            return jsonify({"access_token": access_token, "refresh_token": refresh_token}), 200
        else:
            return jsonify({"message": "Invalid credentials"}), 401

    @app.route("/protected")
    @auth.verify()
    def protected():
        return jsonify({"message": "Access granted"}), 200

    return app


@pytest.fixture
def client(app):
    return app.test_client()


def test_jwt_token_generation(client):
    response = client.post(
        "/auth/jwt/login", json={"username": "testuser", "password": "password123"})
    assert response.status_code == 200
    assert "access_token" in response.json
    assert "refresh_token" in response.json


def test_protected_route_access(client):
    """Test access to protected route with valid JWT token"""
    login_response = client.post(
        "/auth/jwt/login", json={"username": "testuser", "password": "password123"})
    token = login_response.json["access_token"]

    response = client.get(
        "/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json["message"] == "Access granted"


def test_refresh_token(client):
    """Test refresh token endpoint"""
    # First, get a valid access token (using the login flow)
    login_response = client.post(
        "/auth/jwt/login", json={"username": "testuser", "password": "password123"})
    assert login_response.status_code == 200
    refresh_token = login_response.json.get("refresh_token")

    # Then, test the refresh endpoint
    refresh_response = client.post(
        "/auth/jwt/refresh", json={"refresh_token": refresh_token})
    print("token...")
    print(refresh_response.json)
    assert refresh_response.status_code == 200
    assert "access_token" in refresh_response.json
