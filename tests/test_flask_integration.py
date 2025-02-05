import pytest
from flask import Flask, jsonify, request
from flycatch_auth import Auth, AuthCoreJwtConfig

class MockUserService:
    def load_user(self, username: str):
        return {"id": "1", "username": "testuser", "password": "password123", "grants": ["read_user"]}

@pytest.fixture
def app():
    app = Flask(__name__)
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
        data = request.json
        username = data.get("username")
        password = data.get("password")

        user = auth.authenticate(username, password)
        if not user:
            return jsonify({"message": "Invalid credentials"}), 401

        access_token = auth.jwt.generate_token(user)
        refresh_token = auth.jwt.generate_refresh_token(user)

        return jsonify({"access_token": access_token, "refresh_token": refresh_token}), 200


    @app.route("/me")
    @auth.verify()
    def get_curr_user():
        return jsonify({"name": "Test User"}), 200

    return app

@pytest.fixture
def client(app):
    return app.test_client()



def test_me_route_with_auth(client):
    login_response = client.post("/auth/jwt/login", json={"username": "testuser", "password": "password123"})
    assert login_response.status_code == 200
    token = login_response.json["access_token"]

    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json["name"] == "Test User"
