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


# class MockUserService(IdentityService):
#     def load_user(self, username: str) -> Identity:
#         return Identity(user_id="1", username="testuser", grants=["read_user"])

#     def create_user(self, username: str, password: str) -> Identity:
#         # Mock implementation for creating a user
#         return Identity(user_id="2", username=username, grants=[])

#     def validate_password(self, password: str, hashed_password: str) -> bool:
#         # Mock implementation for validating a password
#         return password == hashed_password
