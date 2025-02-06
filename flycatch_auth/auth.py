from typing import Optional
from routes.jwt_routes import create_jwt_routes
from .flask_auth import FlaskAuth
from .identity import Identity
# from .fastapi_auth import FastAPIAuth


class Auth(FlaskAuth):
    def __init__(self, user_service, credential_checker, jwt=None):
        self.user_service = user_service
        self.credential_checker = credential_checker
        self.jwt = jwt

        # Initialize FlaskAuth and FastAPIAuth
        FlaskAuth.__init__(self, user_service, credential_checker, jwt)
        # FastAPIAuth.__init__(self, user_service, credrintrint(user["password"]) (user["password"]) ential_checker, jwt)

    def init_app(self, app):
        """Initialize Auth with Flask"""

        app.auth = self
        create_jwt_routes(self)

    def authenticate(self, username: str, password: str) -> Optional[Identity]:
        """Use to authenticate user"""
        user = self.user_service.load_user(username)
        if user and self.credential_checker(password, user["password"]):
            return user
        return None

    def login(self, username, password):
        """Authenticate user and return JWT token"""
        user = self.authenticate(username, password)
        if user:
            access_token = self.jwt.generate_token(user)
            refresh_token = self.jwt.generate_refresh_token(user)
            return {"access_token": access_token, "refresh_token": refresh_token}
        return {"error": "Invalid credentials"}

    def refresh(self, refresh_token: str):
        """Refresh the access token using a valid refresh token"""
        user = self.jwt.verify_refresh_token(refresh_token)
        if user:
            access_token = self.jwt.generate_token(user)
            return {"access_token": access_token}
        return {"error": "Invalid refresh token"}

    def verify(self):
        """Verify token for Flask or FastAPI"""
        def wrapper(func):
            if hasattr(self, 'flask_verify'):
                return self.flask_verify(func)  # Flask verification
            elif hasattr(self, 'fastapi_verify'):
                return self.fastapi_verify(func)  # FastAPI verification
            return func
        return wrapper

    def has_grants(self, required_grants):
        """General method to return the correct grant-based verification"""
        return {
            "flask": self.flask_has_grants(required_grants),
            # "fastapi": self.fastapi_has_grants(required_grants),
        }
