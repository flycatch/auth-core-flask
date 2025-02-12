import jwt
import logging
from functools import wraps
from flask import request, jsonify
from .model_types import api_response
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
                return api_response(401, "Unauthorized access attempt",False)
            if auth_service.jwt_config.get("enable"):
                try:
                    token = auth_header.split(" ")[1]  # Extract the token
                    decoded_token = jwt.decode(
                        token, auth_service.jwt_config.get('secret'), algorithms=["HS256"])

                    logger.info(
                        f"User {decoded_token['username']} authenticated successfully")
                    request.user = decoded_token  # Attach user info to request
                    return f(*args, **kwargs)

                except jwt.ExpiredSignatureError:
                    logger.warning("Token expired")
                    return api_response(403, "Token expired", False)
                except jwt.InvalidTokenError:
                    logger.warning("Invalid token")
                    return api_response(401, "Invalid token", False)

        return wrapper

    return decorator
