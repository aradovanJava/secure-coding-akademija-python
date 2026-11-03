"""Lab12 – A07 Authentication Failures: JWT propusti (CWE-347, CWE-798, CWE-613).

Koristi ``JwtService`` (jwt_service.py) s RANJIVOM verifikacijom (alg:none, bez provjere exp,
usporedba potpisa operatorom ==) i slabom, hardkodiranom tajnom ``secret123`` (config.py).

Napomena: ova vježba NE koristi zajednički token iz /api/auth/login, nego vlastiti JWT u istom
zaglavlju ``Authorization: Bearer <jwt>``.
"""

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel

from vulnshop.common.auth import DbDep, bearer_scheme
from vulnshop.common.http import error
from vulnshop.common.passwords import verify_password
from vulnshop.lab12.jwt_service import JwtService

router = APIRouter(tags=["Lab12 – JWT"])

BearerDep = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)]


def get_jwt_service(request: Request) -> JwtService:
    return request.app.state.lab12_jwt


JwtDep = Annotated[JwtService, Depends(get_jwt_service)]


class LoginRequest(BaseModel):
    username: str | None = None
    password: str | None = None


@router.post("/api/lab12/login")
def login(body: LoginRequest, db: DbDep, jwt: JwtDep):
    if not body.username or body.password is None:
        return error(401, "Neispravni podaci.")
    row = db.query_one("SELECT username, password, role FROM users WHERE username = ?", (body.username,))
    if row is None or not verify_password(row["password"], body.password):
        return error(401, "Neispravni podaci.")
    token = jwt.create_token(row["username"], row["role"], datetime.now(UTC) + timedelta(minutes=15))
    return {"token": token, "role": row["role"]}


@router.get("/api/lab12/me")
def me(credentials: BearerDep, jwt: JwtDep):
    claims = jwt.verify(credentials.credentials) if credentials else None
    if claims is None:
        return error(401, "Neispravan token.")
    return {"sub": claims.get("sub"), "role": claims.get("role")}


@router.get("/api/lab12/admin")
def admin(credentials: BearerDep, jwt: JwtDep):
    claims = jwt.verify(credentials.credentials) if credentials else None
    if claims is None:
        return error(401, "Neispravan token.")
    if claims.get("role") != "ADMIN":
        return error(403, "Samo administrator.")
    return {"status": "admin ok", "sub": claims.get("sub")}
