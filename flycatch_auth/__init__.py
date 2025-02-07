from .auth import AuthCore 
from .model_types import Identity, IdentityService
from .services import AuthCoreJwtConfig, JwtService

auth = AuthCore()

# It enables top-level imports like `from flycatch_auth import auth, AuthCoreJwtConfig, JwtService`
__all__ = ["auth", "Identity", "IdentityService", "AuthCoreJwtConfig", "JwtService"]