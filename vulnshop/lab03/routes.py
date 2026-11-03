"""Lab03 – A01 Broken Access Control: Server-Side Request Forgery (CWE-918).

RANJIVO: endpoint "pregled poveznice" dohvaća proizvoljan URL koji je zadao korisnik i
vraća početak sadržaja. Nema provjere sheme ni odredišta, pa napadač može dosegnuti interne
servise (loopback, cloud metadata 169.254.169.254) ili lokalne datoteke (file://).

Meta napada je interni endpoint ``/internal/admin/secrets`` koji vraća tajne SAMO kad zahtjev
dolazi s loopback adrese (simulira servis dostupan samo "iznutra").
"""

import urllib.request

from fastapi import APIRouter, Request

from vulnshop.common.auth import CurrentUserDep
from vulnshop.common.http import error

router = APIRouter(tags=["Lab03 – SSRF"])

MAX_CHARS = 2000


@router.get("/api/lab03/preview")
def preview(url: str, user: CurrentUserDep):
    try:
        # RANJIVO: nikakva provjera sheme ni hosta. urllib podržava i file:// i ftp://,
        # a automatski slijedi i preusmjeravanja (redirect).
        with urllib.request.urlopen(url, timeout=5) as response:
            data = response.read(MAX_CHARS)
        return {"url": url, "content": data.decode("utf-8", errors="replace")}
    except ValueError:
        return error(400, "Neispravan URL.")
    except Exception as exc:
        # Nedostupan host, nepodržana shema i sl. -> 502.
        return error(502, f"Dohvat nije uspio: {exc}")


LOOPBACK_HOSTS = {"127.0.0.1", "::1"}


@router.get("/internal/admin/secrets", tags=["Lab03 – SSRF"])
def internal_secrets(request: Request):
    """Interni servis: dostupan samo s loopback adrese (nije zaštićen tokenom)."""
    client_host = request.client.host if request.client else ""
    if client_host not in LOOPBACK_HOSTS and not client_host.startswith("127."):
        return error(403, "Dostupno samo s loopback adrese.")
    return {"dbPassword": "Sup3rTajn0!", "paymentApiKey": "sk_live_akademija_123"}
