import jwt
import datetime
from typing import Optional, Dict
from .base import AuthService
from flycatch_auth.model_types import IdentityService, AuthCoreJwtConfig, api_response


class JwtAuthService(AuthService):
    """JWT-based authentication service."""

    def __init__(self, user_service: IdentityService, credential_checker, jwt_config: AuthCoreJwtConfig):
        self.user_service = user_service
        self.credential_checker = credential_checker
        self.jwt_config = jwt_config

    def authenticate(self, username: str, password: str) -> Optional[Dict]:
        """Authenticate user credentials."""
        user = self.user_service.load_user(username)
        if user and self.credential_checker(password, user["password"]):
            return user
        return None

    def generate_token(self, user, token_type="access") -> str:
        """Generate JWT access or refresh token."""
        expiration = (
            datetime.datetime.utcnow() + datetime.timedelta(hours=8)
            if token_type == "access"
            else datetime.datetime.utcnow() + datetime.timedelta(days=7)
        )

        payload = {
            "id": user["id"],
            "username": user["username"],
            "type": token_type,
            "exp": expiration,
        }
        return jwt.encode(payload, self.jwt_config.get('secret'), algorithm="HS256")

    def decode_token(self, token: str) -> Optional[dict]:
        """Decode JWT token and return user data"""
        try:
            return jwt.decode(token, self.secret, algorithms=["HS256"])
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return None

    def verify_token(self, token: str) -> bool:
        """Verify JWT token"""
        return self.decode_token(token) is not None

    def verify_refresh_token(self, token: str) -> bool:
        """Verify JWT refresh token"""
        return self.decode_token(token) is not None

    def login(self, username: str, password: str) -> Dict:
        """Authenticate and return JWT access & refresh tokens."""
        user = self.authenticate(username, password)
        if user:
            return api_response(200, "Login successful", True, {
                "access_token": self.generate_token(user, "access"),
                "refresh_token": self.generate_token(user, "refresh"),
            })
        return api_response(401, "Invalid credentials", False)

    def refresh(self, refresh_token: str) -> Dict:
        """Refresh JWT access token."""
        try:
            decoded_token = jwt.decode(
                refresh_token, self.jwt_config.get('secret'), algorithms=["HS256"])
            if decoded_token.get("type") != "refresh":
                return {"error": "Invalid token type"}

            user = {"id": decoded_token["id"],
                    "username": decoded_token["username"]}
            return api_response(200, "Token refreshed", True, {"access_token": self.generate_token(user, "access"), "refresh_token": self.generate_token(user, "refresh")})
        except jwt.ExpiredSignatureError:
            return api_response(403, "Refresh token expired", False)
        except jwt.InvalidTokenError:
            return api_response(403, "Invalid refresh token", False)
