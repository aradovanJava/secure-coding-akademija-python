"""Lab14 – A09 Security Logging & Alerting Failures (CWE-778, CWE-117, CWE-532) – ISPRAVLJENO.

POPRAVAK:

* tajne (lozinke, tokeni) se NIKAD ne zapisuju u log,
* korisnički unos se prije zapisa neutralizira: znakovi CR/LF (i ostali kontrolni znakovi)
  zamjenjuju se znakom ``_``, pa napadač ne može krivotvoriti nove retke (log injection),
* bilježe se sigurnosni događaji: ``SECURITY_EVENT LOGIN_FAILED`` (WARNING) i
  ``SECURITY_EVENT LOGIN_SUCCESS`` (INFO), s korisničkim imenom i IP adresom,
* nakon 5 neuspjeha za istog korisnika unutar 5 minuta bilježi se
  ``SECURITY_ALERT BRUTE_FORCE_SUSPECTED`` (ERROR) – na to reagira SIEM / dežurni tim.

U praksi: strukturirani (JSON) zapisi, centralizacija logova (SIEM), korelacijski ID zahtjeva
i zaštita samih logova od izmjene.
"""

import logging
import re
import threading
import time
from collections import defaultdict, deque

from fastapi import APIRouter, Request
from pydantic import BaseModel

from vulnshop.common.auth import DbDep
from vulnshop.common.http import error
from vulnshop.common.passwords import verify_password

router = APIRouter(tags=["Lab14 – Sigurnosno bilježenje"])

log = logging.getLogger("vulnshop.lab14")

ALERT_THRESHOLD = 5
ALERT_WINDOW_SECONDS = 5 * 60
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def sanitize(value: str) -> str:
    """POPRAVAK: neutralizacija CR/LF i ostalih kontrolnih znakova (CWE-117)."""
    return _CONTROL_CHARS.sub("_", value)[:100]


class FailureTracker:
    """Pamti vremena neuspjelih prijava po korisniku (klizni prozor)."""

    def __init__(self) -> None:
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def add(self, username: str) -> int:
        now = time.monotonic()
        with self._lock:
            window = self._failures[username]
            window.append(now)
            while window and now - window[0] > ALERT_WINDOW_SECONDS:
                window.popleft()
            return len(window)


_tracker = FailureTracker()


class LoginRequest(BaseModel):
    username: str | None = None
    password: str | None = None


@router.post("/api/lab14/login")
def login(body: LoginRequest, request: Request, db: DbDep):
    username = body.username or ""
    password = body.password or ""
    safe_user = sanitize(username)
    client_ip = request.client.host if request.client else "-"
    # POPRAVAK: lozinka se ne zapisuje; korisničko ime je neutralizirano.
    row = db.query_one("SELECT password FROM users WHERE username = ?", (username,))
    if row is None or not verify_password(row["password"], password):
        # POPRAVAK: neuspjela prijava je sigurnosni događaj.
        log.warning("SECURITY_EVENT LOGIN_FAILED user=%s ip=%s", safe_user, client_ip)
        if _tracker.add(username) >= ALERT_THRESHOLD:
            log.error("SECURITY_ALERT BRUTE_FORCE_SUSPECTED user=%s ip=%s", safe_user, client_ip)
        return error(401, "Neispravni podaci.")
    log.info("SECURITY_EVENT LOGIN_SUCCESS user=%s ip=%s", safe_user, client_ip)
    return {"status": "prijavljen", "username": username}
