import jwt
import datetime

class AuthCoreJwtConfig:
    def __init__(self, enable=True, secret="secret", expiresIn="1h", refresh=True, prefix="/auth/jwt"):
        self.enable = enable
        self.secret = secret
        self.expiresIn = expiresIn
        self.refresh = refresh
        self.prefix = prefix

class JWTAuth:
    """generate and verify jwt token"""
    def __init__(self, config: AuthCoreJwtConfig):
        self.config = config

    def generate_token(self, user):
        payload = {
            "sub": user["id"],
            "username": user["username"],
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }
        return jwt.encode(payload, self.config.secret, algorithm="HS256")

    def verify_token(self, token):
        try:
            return jwt.decode(token, self.config.secret, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return None
