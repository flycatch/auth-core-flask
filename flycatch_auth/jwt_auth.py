import jwt
import datetime


class AuthCoreJwtConfig:
    def __init__(self, enable, secret, expiresIn, refresh, prefix):
        self.enable = enable
        self.secret = secret
        self.expiresIn = expiresIn
        self.refresh = refresh
        self.prefix = prefix

    def generate_token(self, user_data):
        """Generate JWT token"""
        payload = {
            "sub": user_data["id"],
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=int(self.expiresIn.replace("h", ""))),
            "username": user_data["username"],
            "grants": user_data["grants"],
        }
        token = jwt.encode(payload, self.secret, algorithm="HS256")

        if isinstance(token, bytes):
            token = token.decode("utf-8")
        return token

    def generate_refresh_token(self, user_data):
        """Generate JWT refresh token"""
        payload = {
            "sub": user_data["id"],
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7),
        }
        token = jwt.encode(payload, self.secret, algorithm="HS256")

        if isinstance(token, bytes):
            token = token.decode("utf-8")
        return token

    def decode_token(self, token):
        """Decode JWT token and return user data"""
        try:
            decoded = jwt.decode(token, self.secret, algorithms=["HS256"])
            return decoded  # Return the user data
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def decode_token(self, token):
        """Decode JWT token and return user data"""
        try:
            decoded = jwt.decode(token, self.secret, algorithms=["HS256"])
            return decoded  # Return the user data
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def verify_token(self, token):
        """Verify JWT token"""
        try:
            jwt.decode(token, self.secret, algorithms=["HS256"])
            return True
        except jwt.ExpiredSignatureError:
            return False
        except jwt.InvalidTokenError:
            return False

    def verify_refresh_token(self, token):
        """Verify JWT refresh token"""
        try:
            jwt.decode(token, self.secret, algorithms=["HS256"])
            return True
        except jwt.ExpiredSignatureError:
            return False
        except jwt.InvalidTokenError:
            return False
