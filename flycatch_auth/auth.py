import logging
# from flask_session import Session
# from authlib.integrations.flask_client import OAuth
from .model_types import IdentityService, Identity, CredentialChecker
from .services import AuthCoreJwtConfig, JwtService
from .routes import create_jwt_routes

logger = logging.getLogger("auth_core")


class AuthCore:
    def __init__(self):
        self.configurations = {}
        self.app = None
        self.oauth = None

    def init_app(self, app, user_service: IdentityService, credential_checker: CredentialChecker, jwt: AuthCoreJwtConfig):
        self.app = app
        self.jwt = jwt
        self.user_service = user_service
        self.credential_checker = credential_checker
    
        if jwt and jwt.enable:
           JwtService(user_service, credential_checker, jwt)
           create_jwt_routes(app, jwt, user_service, credential_checker)

            
        # if configurations.get("session", {}).get("enabled", False):
        #     self.setup_session(app, configurations["session"])

        # if configurations.get("google", {}).get("enabled", False):
        #     self.setup_google_auth(app, configurations["google"])

    # def setup_session(self, app, session_config):
    #     app.config["SESSION_TYPE"] = session_config.get("type", "filesystem")
    #     app.config["SESSION_PERMANENT"] = session_config.get("permanent", False)
    #     app.config["SESSION_USE_SIGNER"] = session_config.get("use_signer", True)
    #     app.config["SESSION_KEY_PREFIX"] = session_config.get("key_prefix", "sess:")
    #     Session(app)

    # def setup_google_auth(self, app, google_config):
    #     self.oauth = OAuth(app)
    #     self.oauth.register(
    #         "google",
    #         client_id=google_config["clientID"],
    #         client_secret=google_config["clientSecret"],
    #         authorize_url="https://accounts.google.com/o/oauth2/auth",
    #         authorize_params=None,
    #         access_token_url="https://accounts.google.com/o/oauth2/token",
    #         access_token_params=None,
    #         client_kwargs={"scope": "openid email profile"},
    #     )

    


    # def verify_google(self):
    #     def decorator(func):
    #         @wraps(func)
    #         def wrapper(*args, **kwargs):
    #             user = session.get("user")
    #             if not user:
    #                 logger.warning("Unauthorized Google OAuth access attempt")
    #                 return jsonify({"error": "Unauthorized"}), 401
    #             request.user = user
    #             return func(*args, **kwargs)
    #         return wrapper
    #     return decorator


auth = AuthCore()
