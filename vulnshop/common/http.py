"""Pomoćne funkcije za HTTP odgovore i zajedničko rukovanje greškama (nije vježba)."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


def error(status_code: int, message: str) -> JSONResponse:
    """Odgovor s greškom u istom obliku kao u Java i .NET verziji: {"error": "..."}."""
    return JSONResponse(status_code=status_code, content={"error": message})


def register_common_handlers(app: FastAPI) -> None:
    """Obrađuje SAMO greške autentikacije/autorizacije (HTTPException) i neispravne zahtjeve.

    Sve ostale iznimke namjerno se prepuštaju zadanom rukovanju (Lab04 i Lab15 pokazuju
    razliku između "procurivanja" detalja greške i generičkih poruka).
    """

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.detail},
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        # 400 (kao u Java/.NET verziji) i bez vraćanja poslanih vrijednosti natrag klijentu.
        fields = [".".join(str(part) for part in err.get("loc", ())) for err in exc.errors()]
        return JSONResponse(status_code=400, content={"error": "Neispravan zahtjev.", "fields": fields})
