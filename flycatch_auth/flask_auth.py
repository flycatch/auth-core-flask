from flask import request, jsonify
from functools import wraps
from .flask_middleware import authenticate_request  # Import the middleware function

class FlaskAuth:
    def __init__(self, user_service, credential_checker, jwt):
        self.user_service = user_service
        self.credential_checker = credential_checker
        self.jwt = jwt

    def flask_verify(self, func):
        """Decorator to verify JWT token in Flask"""
        @wraps(func)
        def wrapper(*args, **kwargs):
            token = request.headers.get("Authorization")
            if not token:
                return jsonify({"error": "Token missing"}), 401

            token = token.replace("Bearer ", "")
            try:
                # Decode the token and attach the user data to the request
                user = self.jwt.decode_token(token)
                if not user:
                    return jsonify({"error": "Invalid token"}), 401
                request.user = user  # Attach user to the request
            except Exception as e:
                return jsonify({"error": str(e)}), 401

            return func(*args, **kwargs)
        return wrapper

    def flask_has_grants(self, required_grants):
        """Flask decorator for grant-based access control"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Check if the user is available in request
                if not hasattr(request, "user") or not request.user:
                    return jsonify({"error": "Unauthorized"}), 401

                user_grants = request.user.get("grants", [])
                print(user_grants)
                # Check if the user has all the required grants
                if not all(grant in user_grants for grant in required_grants):
                    return jsonify({"error": "Forbidden"}), 403

                return func(*args, **kwargs)
            return wrapper
        return decorator
