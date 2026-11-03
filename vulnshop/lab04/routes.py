"""Lab04 – A02 Security Misconfiguration: demonstracijski endpointi.

* ``/api/lab04/ping`` – ispravan endpoint (na njemu se provjeravaju sigurnosna zaglavlja),
* ``/api/lab04/crash`` – baca iznimku s osjetljivom porukom (procurivanje tracebacka u debug načinu),
* ``/api/lab04/debug/config`` – RANJIVO: vraća cijelu konfiguraciju, uključujući tajne
  (analogno ``/actuator/env`` u Spring Bootu i debug stranicama u drugim okvirima).
"""

import os
import platform
import sys
from dataclasses import asdict

from fastapi import APIRouter, Request

router = APIRouter(tags=["Lab04 – Sigurnosna konfiguracija"])


@router.get("/api/lab04/ping")
def ping():
    return {"status": "ok", "message": "pong"}


@router.get("/api/lab04/crash")
def crash():
    # Namjerno baca iznimku s osjetljivom porukom (simulira internu grešku).
    raise RuntimeError("Neočekivana greška pri obradi narudžbe: veza s bazom sqlite3 :memory: je pala")


@router.get("/api/lab04/debug/config")
def debug_config(request: Request):
    # RANJIVO: dijagnostički endpoint ostavljen u aplikaciji, bez autentikacije.
    # Otkriva sve postavke (PAYMENT_API_KEY, JWT tajnu ...) i podatke o okruženju.
    return {
        "settings": asdict(request.app.state.settings),
        "python": sys.version,
        "platform": platform.platform(),
        "workingDirectory": os.getcwd(),
    }
