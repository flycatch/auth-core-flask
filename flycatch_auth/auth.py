# module for handle authentication

class Auth:
    def __init__(self, user_service, credential_checker):
        self.user_service = user_service
        self.credential_checker = credential_checker

    def authenticate(self, username, password):
        """Use to authenticate user"""
        user = self.user_service.load_user(username)
        if user and self.credential_checker(password, user["password"]):
            return user
        return None
