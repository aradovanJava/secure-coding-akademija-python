"""Lab14 – A09 Security Logging & Alerting Failures (CWE-778, CWE-117, CWE-532).

RANJIVO:

* lozinka se zapisuje u log (CWE-532),
* korisničko ime zapisuje se bez neutralizacije CR/LF, pa napadač može krivotvoriti lažne
  retke u logu (log injection, CWE-117),
* neuspjela prijava NE bilježi se kao sigurnosni događaj (CWE-778), pa nema ni otkrivanja
  brute force napada.
"""

import logging

from fastapi import APIRouter
from pydantic import BaseModel

from vulnshop.common.auth import DbDep
from vulnshop.common.http import error
from vulnshop.common.passwords import verify_password

router = APIRouter(tags=["Lab14 – Sigurnosno bilježenje"])

log = logging.getLogger("vulnshop.lab14")


class LoginRequest(BaseModel):
    username: str | None = None
    password: str | None = None


@router.post("/api/lab14/login")
def login(body: LoginRequest, db: DbDep):
    username = body.username or ""
    password = body.password or ""
    # RANJIVO: lozinka u logu + korisničko ime bez neutralizacije CR/LF.
    log.info("Login attempt user=" + username + " password=" + password)
    row = db.query_one("SELECT password FROM users WHERE username = ?", (username,))
    if row is None or not verify_password(row["password"], password):
        # RANJIVO: neuspjeh se ne bilježi kao sigurnosni događaj (nema ni otkrivanja brute forcea).
        return error(401, "Neispravni podaci.")
    log.info("Login successful user=" + username)
    return {"status": "prijavljen", "username": username}
