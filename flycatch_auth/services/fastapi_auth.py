from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPBearer
from starlette.requests import Request

security = HTTPBearer()


class FastAPIAuth:
    def __init__(self, user_service, credential_checker, jwt):
        self.user_service = user_service
        self.credential_checker = credential_checker
        self.jwt = jwt

    async def fastapi_verify(self, request: Request, token: str = Security(security)):
        """Verify JWT token in FastAPI"""
        if not token.credentials or not self.jwt.verify_token(token.credentials):
            raise HTTPException(status_code=401, detail="Unauthorized")
        return self.jwt.verify_token(token.credentials)  # Return user payload

    def fastapi_has_grants(self, required_grants):
        """FastAPI dependency for grant-based access control"""
        async def dependency(token: str = Security(security)):
            payload = self.jwt.verify_token(token.credentials)
            if not payload:
                raise HTTPException(status_code=401, detail="Unauthorized")

            user_grants = payload.get("grants", [])
            if not all(grant in user_grants for grant in required_grants):
                raise HTTPException(status_code=403, detail="Forbidden")

            return payload  # Return user payload for further use in FastAPI routes

        return dependency
