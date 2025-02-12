import jwt
import logging
from functools import wraps
from flask import request, jsonify

logger = logging.getLogger("auth_core")


def verify_request(auth_service):
    """Middleware function to verify authentication."""

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization")

            if not auth_header:
                logger.warning(
                    "Unauthorized access attempt: Missing Authorization header")
                return jsonify({"error": "Unauthorized"}), 401
            if auth_service.jwt_config.enable:
                try:
                    token = auth_header.split(" ")[1]  # Extract the token
                    decoded_token = jwt.decode(
                        token, auth_service.jwt_config.secret, algorithms=["HS256"])

                    logger.info(
                        f"User {decoded_token['username']} authenticated successfully")
                    request.user = decoded_token  # Attach user info to request
                    return f(*args, **kwargs)

                except jwt.ExpiredSignatureError:
                    logger.warning("Token expired")
                    return jsonify({"error": "Token expired"}), 403
                except jwt.InvalidTokenError:
                    logger.warning("Invalid token")
                    return jsonify({"error": "Invalid token"}), 403

        return wrapper

    return decorator
