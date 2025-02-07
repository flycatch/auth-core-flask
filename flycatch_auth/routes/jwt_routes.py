from flask import Blueprint, request, jsonify
import jwt
import datetime
import logging

logger = logging.getLogger(__name__)


def create_jwt_routes(app, config, user_service, credential_checker):
    router = Blueprint("jwt_auth", __name__)
    prefix = config.prefix or "/auth/jwt"

    def create_access_token(user):
        """Generate JWT Access Token"""
        payload = {
            "id": user["id"],
            "username": user["username"],
            "type": "access",
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=8),
        }
        return jwt.encode(payload, config.secret, algorithm="HS256")

    def create_refresh_token(user):
        """Generate JWT Refresh Token"""
        payload = {
            "id": user["id"],
            "username": user["username"],
            "type": "refresh",
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7),
        }
        return jwt.encode(payload, config.secret, algorithm="HS256")

    @router.route(f"{prefix}/login", methods=["POST"])
    def login():
        """Login route to generate access and refresh tokens"""
        data = request.json
        username, password = data.get("username"), data.get("password")
        logger.info(f"Login attempt for username: {username}")
        
        user = user_service.load_user(username)
        if not user or not credential_checker(password, user["password"]):
            logger.warning(f"Login failed for username: {username}")
            return jsonify({"error": "Invalid username or password"}), 401
        
        access_token = create_access_token(user)
        refresh_token = create_refresh_token(user)
        logger.info(f"Login successful for username: {username}")
        return jsonify({"access_token": access_token, "refresh_token": refresh_token})

    @router.route(f"{prefix}/refresh", methods=["POST"])
    def refresh():
        """Refresh access token using a valid refresh token"""
        auth_header = request.headers.get("Authorization")
        logger.info("Refresh token attempt received")
        if not auth_header:
            logger.warning("Refresh token missing in request")
            return jsonify({"error": "Refresh token is required"}), 400

        try:
            refresh_token = auth_header.split(" ")[1]
            decoded_token = jwt.decode(refresh_token, config.secret, algorithms=["HS256"])
            
            if decoded_token.get("type") != "refresh":
                logger.warning("Invalid token type for refresh")
                return jsonify({"error": "Invalid token type"}), 403
            
            user = {"id": decoded_token["id"], "username": decoded_token["username"]}
            access_token = create_access_token(user)
            new_refresh_token = create_refresh_token(user)

            logger.info(f"Access token refreshed for username: {user['username']}")
            return jsonify({"access_token": access_token, "refresh_token": new_refresh_token})
        except jwt.ExpiredSignatureError:
            logger.warning("Refresh token expired")
            return jsonify({"error": "Refresh token expired"}), 403
        except jwt.InvalidTokenError:
            logger.warning("Invalid refresh token provided")
            return jsonify({"error": "Invalid refresh token"}), 403
        except Exception as e:
            logger.error("JWT Refresh Error", exc_info=True)
            return jsonify({"error": "Internal Server Error"}), 500

    app.register_blueprint(router)
