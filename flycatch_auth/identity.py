class Identity:
    def __init__(self, user_id, username, grants):
        self.id = user_id
        self.username = username
        self.grants = grants

class IdentityService:
    def load_user(self, username: str) -> Identity:
        """Override this method to fetch user from DB"""
        raise NotImplementedError("Must implement `load_user` method")
