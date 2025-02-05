# Flycatch Auth

Flycatch Auth is a Python authentication package that provides JWT-based authentication with grant-based access control for both Flask and FastAPI applications.

## Features

- **JWT authentication**:Supports access and refresh tokens with customizable expiry times.

- **Grant-based access control**

- **Works with Flask and FastAPI**

- **Simple integration with existing user services**

## Installation

Install flycatch_auth using pip:

```bash
pip install flycatch-auth
```

## Usage

```python

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

app = Flask(__name__)

auth = Auth(
    user_service=MockUserService(),
    credential_checker=lambda input, user: input == user["password"],
    jwt=AuthCoreJwtConfig(
        enable=True,
        secret="your-secret-key",
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

@app.route("/protected")
@auth.verify()
def protected():
    return jsonify({"message": "Access granted"}), 200

if __name__ == "__main__":
    app.run(debug=True)
```
This snippet demonstrates how to configure and initialize Auth using MockUserService and JWT-based authentication

## Configuration Options

### JWT Configuration

```python
jwt_config = {
    "enabled": True,
    "secret": "your-jwt-secret",
    "expiresIn": "8h",  # Expiry time for JWT
    "refreshToken": True,  # Enable refresh tokens
    "prefix": "/auth/jwt",  # Prefix for JWT-related routes
}
```

### Password Checker

```python
credential_checker=lambda input, user: input == user["password"],
```

## License

This project is licensed under the GPL-3.0 License.

---

For more details and advanced use cases, visit the [GitHub repository](#) or contact the project maintainers.

```

```
