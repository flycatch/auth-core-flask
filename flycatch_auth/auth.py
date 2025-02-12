import logging
# from flask_session import Session
# from authlib.integrations.flask_client import OAuth
from .model_types import IdentityService, CredentialChecker
from .services import AuthCoreJwtConfig, JwtAuthService
from .routes import create_jwt_routes
from .middleware import verify_request
logger = logging.getLogger("auth_core")


class AuthCore:
    def __init__(self):
        self.app = None
        self.jwt = None
        self.user_service = None
        self.credential_checker = None
        self.auth_service = None

    def init_app(
        self,
        app,
        user_service: IdentityService,
        credential_checker: CredentialChecker,
        jwt: AuthCoreJwtConfig,
    ):
        """Initialize authentication with JWT if enabled."""
        self.app = app
        self.jwt = jwt
        self.user_service = user_service
        self.credential_checker = credential_checker

        if jwt and jwt.enable:
            # Initialize JWT authentication service
            self.auth_service = JwtAuthService(
                user_service, credential_checker, jwt)

            # Set up JWT authentication routes
            create_jwt_routes(app, jwt, user_service, credential_checker)

        return self.auth_service

    def verify(self):
        """Middleware to verify authentication."""
        return verify_request(self.auth_service)


auth = AuthCore()
