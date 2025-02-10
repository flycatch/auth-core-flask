from typing import Dict, Optional
from .base import AuthService


class SessionAuthService(AuthService):
    """Session-based authentication service (to be implemented)."""

    def authenticate(self, username: str, password: str) -> Optional[Dict]:
        """Authenticate user using session management."""
        pass

    def login(self, username: str, password: str) -> Dict:
        """Handle user login via session."""
        pass

    def refresh(self, refresh_token: str) -> Dict:
        """Refresh session authentication (if applicable)."""
        pass
