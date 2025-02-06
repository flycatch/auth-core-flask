from abc import ABC, abstractmethod
from typing import List, Optional

class Identity(ABC):
    """Manage user authentication and authorization."""
    def __init__(self, user_id: str, username: str, grants: List[str]):
        self.id = user_id
        self.username = username
        self.grants = grants

    @abstractmethod
    def has_grant(self, grant: str) -> bool:
        """Check if the identity has a specific grant."""
        pass

class IdentityService(ABC):
    @abstractmethod
    def load_user(self, username: str) -> Optional[Identity]:
        """Override this method to fetch a user from DB."""
        pass

    @abstractmethod
    def create_user(self, username: str, password: str) -> Identity:
        """Override this method to create a new user in DB."""
        pass

    @abstractmethod
    def validate_password(self, password: str, hashed_password: str) -> bool:
        """Override this method to validate password."""
        pass
