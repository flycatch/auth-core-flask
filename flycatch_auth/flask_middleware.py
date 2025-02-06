from flask import request, jsonify

def authenticate_request(jwt):
    """Middleware to authenticate the request by checking the JWT token."""
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Authorization token is missing"}), 401

    token = token.replace("Bearer ", "")  # Remove 'Bearer ' part
    user = jwt.verify_token(token)
    if not user:
        return jsonify({"message": "Invalid or expired token"}), 401

    # Set the authenticated user in the request context
    request.user = user
