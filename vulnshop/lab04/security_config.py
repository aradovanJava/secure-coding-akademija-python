"""Lab04 – sigurnosna konfiguracija aplikacije (CWE-16, CWE-209, CWE-942, CWE-693) – ISPRAVLJENO.

POPRAVAK:

* ``config.py``: ``debug`` je po zadanom isključen,
* CORS: samo origini s popisa (``CORS_ALLOWED_ORIGINS``), ne refleksija bilo kojeg origina,
* sigurnosna HTTP zaglavlja na svakom odgovoru (nosniff, X-Frame-Options, CSP, Referrer-Policy),
* generički odgovor na neočekivanu grešku (RFC 9457 "problem details") s korelacijskim ID-om;
  detalji ostaju samo u logu poslužitelja,
* ``routes.py``: dijagnostički endpoint ``/api/lab04/debug/config`` je uklonjen.
"""

import logging
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

log = logging.getLogger("vulnshop.errors")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'self'",
    "Referrer-Policy": "no-referrer",
}
# Swagger UI (/docs) učitava skripte s CDN-a pa mu se ne postavlja strogi CSP.
# U produkciji se /docs isključuje (FastAPI(docs_url=None, redoc_url=None)) ili štiti prijavom.
DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")


def init(app: FastAPI) -> None:
    settings = app.state.settings

    # POPRAVAK: CORS allowlista iz konfiguracije.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT"],
        allow_headers=["Authorization", "Content-Type"],
    )

    # POPRAVAK: sigurnosna zaglavlja (ne prepisuju se zaglavlja koja je endpoint već postavio).
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            if name == "Content-Security-Policy" and request.url.path.startswith(DOCS_PATHS):
                continue
            response.headers.setdefault(name, value)
        return response

    # POPRAVAK: generička poruka za neočekivanu grešku; detalji samo u logu, uz korelacijski ID.
    @app.exception_handler(Exception)
    async def unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
        correlation_id = str(uuid.uuid4())
        log.error("Neobrađena greška correlationId=%s path=%s", correlation_id, request.url.path, exc_info=exc)
        return JSONResponse(
            status_code=500,
            media_type="application/problem+json",
            content={
                "type": "about:blank",
                "title": "Interna greška poslužitelja",
                "status": 500,
                "detail": "Došlo je do neočekivane greške. Pokušajte ponovno kasnije.",
                "correlationId": correlation_id,
            },
        )
