import jwt
import datetime
from typing import Optional
from dataclasses import dataclass
from flycatch_auth.model_types import Identity, IdentityService


@dataclass
class AuthCoreJwtConfig:
    enable: bool
    secret: str
    expiresIn: str
    refresh: bool
    prefix: str

    def generate_token(self, user_data: dict) -> str:
        """Generate JWT access token"""
        exp_hours = int(self.expiresIn.replace("h", ""))
        payload = {
            "sub": user_data["id"],
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=exp_hours),
            "username": user_data["username"],
            "grants": user_data["grants"],
        }
        return jwt.encode(payload, self.secret, algorithm="HS256")

    def generate_refresh_token(self, user_data: dict) -> str:
        """Generate JWT refresh token"""
        payload = {
            "sub": user_data["id"],
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7),
        }
        return jwt.encode(payload, self.secret, algorithm="HS256")

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


class JwtService:
    def __init__(self, user_service: IdentityService, credential_checker, jwt_config: AuthCoreJwtConfig):
        self.user_service = user_service
        self.credential_checker = credential_checker
        self.jwt_config = jwt_config

    def authenticate(self, username: str, password: str) -> Optional[Identity]:
        """Authenticate user"""
        user = self.user_service.load_user(username)
        if user and self.credential_checker(password, user["password"]):
            return user
        return None

    def login(self, username: str, password: str) -> dict:
        """Authenticate user and return JWT tokens"""
        user = self.authenticate(username, password)
        if user:
            return {
                "access_token": self.jwt_config.generate_token(user),
                "refresh_token": self.jwt_config.generate_refresh_token(user),
            }
        return {"error": "Invalid credentials"}

    def refresh(self, refresh_token: str) -> dict:
        """Refresh access token using a valid refresh token"""
        user_data = self.jwt_config.decode_token(refresh_token)
        if user_data:
            return {"access_token": self.jwt_config.generate_token(user_data)}
        return {"error": "Invalid refresh token"}
