"""Tvornica aplikacije: stvara FastAPI aplikaciju sa svježom bazom i svim vježbama.

Svaki poziv ``create_app()`` daje novu instancu s novom bazom u memoriji – tako i
testovi dobivaju čisto početno stanje.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI

from vulnshop import (
    lab01,
    lab02,
    lab03,
    lab04,
    lab05,
    lab06,
    lab07,
    lab08,
    lab09,
    lab10,
    lab11,
    lab12,
    lab13,
    lab14,
    lab15,
)
from vulnshop.common import auth
from vulnshop.common.auth import TokenStore
from vulnshop.common.data import init_users
from vulnshop.common.db import Database
from vulnshop.common.http import register_common_handlers
from vulnshop.config import Settings

LABS = (lab01, lab02, lab03, lab04, lab05, lab06, lab07, lab08, lab09, lab10, lab11, lab12, lab13, lab14, lab15)

DESCRIPTION = """
**Namjerno ranjiva** web trgovina za vježbe sigurnog programiranja (Span Centar kibernetičke sigurnosti).
Pokrećite je **samo lokalno**.

1. Prijavite se preko `POST /api/auth/login` (npr. `ana` / `Ana123!`).
2. Kopirajte `token` iz odgovora i kliknite **Authorize** (gore desno).
3. Upute za svaku vježbu nalaze se u mapi `docs/labs/`.
"""


def _configure_logging() -> None:
    logger = logging.getLogger("vulnshop")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s"))
        logger.addHandler(handler)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    _configure_logging()

    app = FastAPI(
        title="VulnShop Akademija (Python / FastAPI)",
        description=DESCRIPTION,
        version="1.0.0",
        debug=settings.debug,  # Lab04 – vidi config.py
    )
    app.state.settings = settings
    app.state.db = Database()
    app.state.tokens = TokenStore()

    register_common_handlers(app)
    init_users(app.state.db)
    app.include_router(auth.router)

    for lab in LABS:
        lab.init(app)
        app.include_router(lab.router)

    @app.get("/", tags=["Opće"])
    def index():
        return {
            "aplikacija": "VulnShop Akademija (Python / FastAPI)",
            "upozorenje": "Namjerno ranjiva aplikacija - pokretati samo lokalno.",
            "dokumentacija": "/docs",
            "prijava": "POST /api/auth/login",
        }

    @app.get("/health", tags=["Opće"])
    def health():
        return {"status": "UP"}

    return app
