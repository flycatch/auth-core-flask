# flycatch_auth/auth/jwt_routes.py

from flask import Blueprint, request, jsonify

auth_bp = Blueprint('auth', __name__, url_prefix='/auth/jwt')

def create_jwt_routes(auth):
    # Delay the import of Auth here to avoid circular import
    from flycatch_auth import Auth  # Import inside the function

    @auth_bp.route("/login", methods=["POST"])
    def login():
        data = request.json
        username = data.get("username")
        password = data.get("password")

        response = auth.login(username, password)
        if "access_token" in response:
            return jsonify(response), 200
        else:
            return jsonify({"message": response["error"]}), 401

    @auth_bp.route("/refresh", methods=["POST"])
    def refresh():
        data = request.json
        refresh_token = data.get("refresh_token")

        response = auth.refresh(refresh_token)
        if "access_token" in response:
            return jsonify(response), 200
        else:
            return jsonify({"message": response["error"]}), 401
