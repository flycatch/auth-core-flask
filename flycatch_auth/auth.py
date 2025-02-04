from .flask_auth import FlaskAuth
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

    def authenticate(self, username, password):
        """Use to authenticate user"""
        user = self.user_service.load_user(username)
        if user and self.credential_checker(password, user["password"]):
            return user
        return None

    def login(self, username, password):
        """Authenticate user and return JWT token"""
        user =  self.authenticate(username, password)
        if user:
            token = self.jwt.generate_token(user)
            return {"access_token": token}
        return {"error": "Invalid credentials"}

    def verify(self):
        """Verify token for Flask or FastAPI"""
        def wrapper(func):
            if hasattr(self, 'flask_verify'):
                return self.flask_verify(func)  # Flask verification
            elif hasattr(self, 'fastapi_verify'):
                return self.fastapi_verify(func)  # FastAPI verification
            return func
        return wrapper
