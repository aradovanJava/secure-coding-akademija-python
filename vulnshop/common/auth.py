"""Zajednička autentikacija (implementirana ISPRAVNO, nije dio vježbi).

``POST /api/auth/login {"username","password"}`` -> 200 s nasumičnim tokenom ako su podaci
točni, inače 401. Token se šalje kao ``Authorization: Bearer <token>``. Zaštićeni endpointi
dobivaju prijavljenog korisnika preko ovisnosti ``CurrentUserDep``.
"""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from vulnshop.common.db import Database
from vulnshop.common.http import error
from vulnshop.common.passwords import verify_password


@dataclass(frozen=True)
class CurrentUser:
    id: int
    username: str
    role: str

    @property
    def is_admin(self) -> bool:
        return self.role == "ADMIN"


class TokenStore:
    """Tokeni u memoriji: nasumičnih 32 bajta (base64url) -> korisnik."""

    def __init__(self) -> None:
        self._tokens: dict[str, CurrentUser] = {}
        self._lock = threading.Lock()

    def issue(self, user: CurrentUser) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._tokens[token] = user
        return token

    def resolve(self, token: str) -> CurrentUser | None:
        with self._lock:
            return self._tokens.get(token)


# Prikazuje gumb "Authorize" u Swagger UI-ju (/docs).
bearer_scheme = HTTPBearer(auto_error=False, description="Token iz POST /api/auth/login")


def get_db(request: Request) -> Database:
    return request.app.state.db


def current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> CurrentUser:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Potrebna je prijava (Authorization: Bearer <token>).")
    user = request.app.state.tokens.resolve(credentials.credentials)
    if user is None:
        raise HTTPException(status_code=401, detail="Neispravan ili istekao token.")
    return user


DbDep = Annotated[Database, Depends(get_db)]
CurrentUserDep = Annotated[CurrentUser, Depends(current_user)]

router = APIRouter(tags=["Prijava (zajedničko)"])


class LoginRequest(BaseModel):
    username: str | None = None
    password: str | None = None


@router.post("/api/auth/login")
def login(body: LoginRequest, request: Request, db: DbDep):
    if not body.username or body.password is None:
        return error(401, "Neispravno korisničko ime ili lozinka.")
    row = db.query_one("SELECT id, username, password, role FROM users WHERE username = ?", (body.username,))
    if row is None or not verify_password(row["password"], body.password):
        return error(401, "Neispravno korisničko ime ili lozinka.")
    user = CurrentUser(id=row["id"], username=row["username"], role=row["role"])
    token = request.app.state.tokens.issue(user)
    return {"token": token, "username": user.username, "role": user.role}
