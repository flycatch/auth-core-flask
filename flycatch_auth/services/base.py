from abc import ABC, abstractmethod
from typing import Optional, Dict


class AuthService(ABC):
    """Abstract base class for authentication services."""

    @abstractmethod
    def authenticate(self, username: str, password: str) -> Optional[Dict]:
        """Authenticate a user and return user data if successful."""
        raise NotImplementedError

    @abstractmethod
    def login(self, username: str, password: str) -> Dict:
        """Handle user login and return authentication tokens or session details."""
        raise NotImplementedError

    @abstractmethod
    def refresh(self, refresh_token: str) -> Dict:
        """Refresh authentication tokens (if applicable)."""
        raise NotImplementedError




