"""Lab12 – JWT propusti: sigurnosni testovi."""

import base64
import hashlib
import hmac
import json
import time
from datetime import UTC, datetime, timedelta

import pytest

pytestmark = [pytest.mark.security, pytest.mark.lab12]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _encode(part: dict) -> str:
    return _b64url(json.dumps(part, separators=(",", ":")).encode())


def _admin_claims() -> dict:
    now = int(time.time())
    return {"sub": "marko", "role": "ADMIN", "iat": now, "exp": now + 600}


def test_alg_none_token_is_rejected(client):
    """Token s "alg": "none", ulogom ADMIN i praznim potpisom mora biti odbijen (401)."""
    token = _encode({"alg": "none", "typ": "JWT"}) + "." + _encode(_admin_claims()) + "."

    response = client.get("/api/lab12/admin", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401


def test_token_signed_with_weak_secret_is_rejected(client):
    """Token potpisan slabom tajnom 'secret123' (pronađenom rječnikom) s ulogom ADMIN mora biti odbijen."""
    signing_input = _encode({"alg": "HS256", "typ": "JWT"}) + "." + _encode(_admin_claims())
    signature = _b64url(hmac.new(b"secret123", signing_input.encode(), hashlib.sha256).digest())

    response = client.get("/api/lab12/admin", headers={"Authorization": f"Bearer {signing_input}.{signature}"})

    assert response.status_code == 401


def test_expired_token_is_rejected(client, app):
    """Istekli token (ispravno potpisan ključem aplikacije) mora biti odbijen (401)."""
    expired = app.state.lab12_jwt.create_token("ana", "USER", datetime.now(UTC) - timedelta(minutes=1))

    response = client.get("/api/lab12/me", headers={"Authorization": f"Bearer {expired}"})

    assert response.status_code == 401
