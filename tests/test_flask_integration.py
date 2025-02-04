import pytest
from flask import Flask, jsonify
from auth_package.flask_auth import FlaskAuth
from auth_package.auth import AuthCoreJwtConfig

@pytest.fixture
def app():
    app = Flask(__name__)
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

    @app.route("/me")
    @auth.verify()
    def get_curr_user():
        return jsonify({"name": "Test User"}), 200

    return app

@pytest.fixture
def client(app):
    return app.test_client()

class MockUserService:
    def load_user(self, username: str):
        return {"id": "1", "username": "testuser", "password": "password123", "grants": ["read_user"]}

def test_me_route_with_auth(client):
    login_response = client.post("/auth/jwt/login", json={"username": "testuser", "password": "password123"})
    token = login_response.json["access_token"]

    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json["name"] == "Test User"
