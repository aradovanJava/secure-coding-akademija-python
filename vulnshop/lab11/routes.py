"""Lab11 – A07 Authentication Failures: brute force i enumeracija (CWE-307, CWE-204) – ISPRAVLJENO.

POPRAVAK:

* jedinstven odgovor 401 "Neispravno korisničko ime ili lozinka." za nepostojećeg korisnika i za
  pogrešnu lozinku (nema enumeracije),
* lozinka se provjerava i za nepostojećeg korisnika (lažni hash) – vrijeme odgovora je
  ujednačeno pa se ni po njemu ne može zaključiti postoji li korisnik,
* nakon 5 neuspjelih pokušaja račun se zaključava na 15 minuta (odgovor 429).

Dodatno u praksi: višefaktorska autentikacija (MFA), CAPTCHA nakon nekoliko neuspjeha,
ograničenje broja zahtjeva po IP adresi (rate limiting) i provjera lozinki protiv popisa
procurjelih lozinki.
"""

import threading
import time

from fastapi import APIRouter, Request
from pydantic import BaseModel

from vulnshop.common.auth import DbDep
from vulnshop.common.http import error
from vulnshop.common.passwords import hash_password, verify_password

router = APIRouter(tags=["Lab11 – Brute force i enumeracija"])

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 15 * 60
GENERIC_ERROR = "Neispravno korisničko ime ili lozinka."
# Lažni hash za nepostojeće korisnike (ujednačeno vrijeme odgovora).
DUMMY_HASH = hash_password("lazna-lozinka-za-ujednaceno-vrijeme")


class LoginAttempts:
    """Brojač neuspjelih prijava po korisničkom imenu (u memoriji)."""

    def __init__(self) -> None:
        self._failures: dict[str, int] = {}
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def is_locked(self, username: str) -> bool:
        with self._lock:
            return self._locked_until.get(username, 0) > time.monotonic()

    def record_failure(self, username: str) -> None:
        with self._lock:
            count = self._failures.get(username, 0) + 1
            self._failures[username] = count
            if count >= MAX_FAILED_ATTEMPTS:
                self._locked_until[username] = time.monotonic() + LOCKOUT_SECONDS
                self._failures[username] = 0

    def reset(self, username: str) -> None:
        with self._lock:
            self._failures.pop(username, None)
            self._locked_until.pop(username, None)


def get_attempts(request: Request) -> LoginAttempts:
    state = request.app.state
    if not hasattr(state, "lab11_attempts"):
        state.lab11_attempts = LoginAttempts()
    return state.lab11_attempts


class LoginRequest(BaseModel):
    username: str | None = None
    password: str | None = None


@router.post("/api/lab11/login")
def login(body: LoginRequest, request: Request, db: DbDep):
    username = body.username or ""
    password = body.password or ""
    attempts = get_attempts(request)
    # POPRAVAK: zaključan račun -> 429 (i prije provjere lozinke).
    if attempts.is_locked(username):
        return error(429, "Previše neuspjelih pokušaja. Pokušajte ponovno kasnije.")

    row = db.query_one("SELECT password_hash FROM lab11_users WHERE username = ?", (username,))
    # POPRAVAK: lozinka se provjerava i kad korisnik ne postoji (lažni hash).
    valid = verify_password(row["password_hash"] if row else DUMMY_HASH, password)
    if row is None or not valid:
        attempts.record_failure(username)
        # POPRAVAK: isti status i ista poruka za oba slučaja.
        return error(401, GENERIC_ERROR)

    attempts.reset(username)
    return {"status": "prijavljen", "username": username}
