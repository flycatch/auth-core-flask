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
from flycatch_auth import auth, AuthCoreJwtConfig

app = Flask(__name__)

class Userservice(IdentityService):
    def load_user(self,username: str) -> Identity:
        user = user_db.get_users()
        return {
                "id": "",
                "username": "",
                "password": "",
                "grants": [list(map(lambda user: user.permission.name, users))] # read_user
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
    user_service=MockUserService(),
    credential_checker=lambda input, user: input == user,
    jwt=jwt_config,
)


@app.route("/me")
@auth.verify()
def get_curr_user():
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
