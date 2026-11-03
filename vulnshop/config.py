"""Konfiguracija aplikacije (analogno datoteci application.properties u Java verziji).

Vrijednosti se čitaju iz varijabli okoline, uz zadane vrijednosti za lokalni rad.
Na grani ``main`` dio postavki je NAMJERNO RANJIV (Lab04, Lab12) – vidi komentare.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "da", "on"}


def _env_list(name: str, default: list[str]) -> list[str]:
    value = os.environ.get(name)
    if not value:
        return list(default)
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    # ---------------------------------------------------------------------------
    # Lab04 – A02 Security Misconfiguration (NAMJERNO RANJIVO na grani main)
    # ---------------------------------------------------------------------------
    # RANJIVO: debug način rada uključen je po zadanom – i u "produkciji".
    # FastAPI/Starlette tada za svaku neobrađenu iznimku vraća cijeli traceback
    # (putanje datoteka, nazive modula i klasa, dijelove koda).
    debug: bool = field(default_factory=lambda: _env_bool("APP_DEBUG", True))

    # Dopušteni CORS origini (koristi ih tek ispravljena konfiguracija u lab04/security_config.py).
    cors_allowed_origins: list[str] = field(
        default_factory=lambda: _env_list("CORS_ALLOWED_ORIGINS", ["http://localhost:3000"])
    )

    # Tajna koju ranjivi endpoint /api/lab04/debug/config otkriva (analogno /actuator/env).
    payment_api_key: str = field(default_factory=lambda: os.environ.get("PAYMENT_API_KEY", "sk_live_akademija_123"))

    # Lab06 dio B – ključ za AES-GCM (Base64, 32 B). Ranjivi kod ga NE koristi (ima hardkodirani ključ).
    # Zadana vrijednost služi SAMO za lokalni rad; u produkciji ključ dolazi iz okoline / KMS-a.
    lab06_encryption_key: str = field(
        default_factory=lambda: os.environ.get("LAB06_KEY", "ZGV2LWtsanVjLVNBTU8temEtbG9rYWxuaS1yYWQhMzI=")
    )

    # Lab12 – RANJIVO: slaba i hardkodirana JWT tajna.
    lab12_jwt_secret: str = "secret123"
