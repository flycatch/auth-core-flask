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
        }
        token = jwt.encode(payload, self.secret, algorithm="HS256")

        if isinstance(token, bytes):
            token = token.decode("utf-8")
        return token


    def verify_token(self, token):
        """Verify JWT token"""
        try:
            jwt.decode(token, self.secret, algorithms=["HS256"])
            return True
        except jwt.ExpiredSignatureError:
            return False
        except jwt.InvalidTokenError:
            return False
