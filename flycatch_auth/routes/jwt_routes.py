from flask import Blueprint, request, jsonify
import logging
from ..services import JwtAuthService

logger = logging.getLogger(__name__)


def create_jwt_routes(app, config, user_service, credential_checker):
    router = Blueprint("jwt_auth", __name__)
    prefix = config.prefix or "/auth/jwt"

    jwt_auth = JwtAuthService(user_service, credential_checker, config)

    @router.route(f"{prefix}/login", methods=["POST"])
    def login():
        """Login route to generate access and refresh tokens"""
        data = request.json
        username, password = data.get("username"), data.get("password")
        return jsonify(jwt_auth.login(username=username, password=password))

    @router.route(f"{prefix}/refresh", methods=["POST"])
    def refresh():
        """Refresh access token using a valid refresh token"""
        auth_header = request.headers.get("Authorization")
        logger.info("Refresh token attempt received")

        if not auth_header:
            logger.warning("Refresh token missing in request")
            return jsonify({"error": "Refresh token is required"}), 400

        refresh_token = auth_header.split(" ")[1]
        response = jwt_auth.refresh(refresh_token)
        return jsonify(response), 200 if "access_token" in response else 403

    app.register_blueprint(router)
