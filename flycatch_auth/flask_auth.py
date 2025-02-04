from flask import request, jsonify

class FlaskAuth:
    def __init__(self, user_service, credential_checker, jwt):
        self.user_service = user_service
        self.credential_checker = credential_checker
        self.jwt = jwt

    def flask_verify(self, func):
        """Decorator to verify JWT token in Flask"""
        def wrapper(*args, **kwargs):
            token = request.headers.get("Authorization")
            if not token or not self.jwt.verify_token(token.replace("Bearer ", "")):
                return jsonify({"error": "Unauthorized"}), 401
            return func(*args, **kwargs)
        return wrapper
