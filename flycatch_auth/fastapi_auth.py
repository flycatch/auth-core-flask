# This file contains the FastAPIAuth class which is used to verify JWT tokens in FastAPI

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
