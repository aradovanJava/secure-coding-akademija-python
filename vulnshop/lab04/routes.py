"""Lab04 – A02 Security Misconfiguration: demonstracijski endpointi – ISPRAVLJENO.

* ``/api/lab04/ping`` – ispravan endpoint (na njemu se provjeravaju sigurnosna zaglavlja),
* ``/api/lab04/crash`` – baca iznimku s osjetljivom porukom; odgovor je sada generički,
* POPRAVAK: dijagnostički endpoint ``/api/lab04/debug/config`` je UKLONJEN (404). Ako je
  dijagnostika potrebna, smije postojati samo u razvojnom okruženju i iza autentikacije.
"""

from fastapi import APIRouter

router = APIRouter(tags=["Lab04 – Sigurnosna konfiguracija"])


@router.get("/api/lab04/ping")
def ping():
    return {"status": "ok", "message": "pong"}


@router.get("/api/lab04/crash")
def crash():
    # Namjerno baca iznimku s osjetljivom porukom (simulira internu grešku).
    raise RuntimeError("Neočekivana greška pri obradi narudžbe: veza s bazom sqlite3 :memory: je pala")
