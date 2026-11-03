"""Lab12 – ručna implementacija JWT-a (HS256) bez vanjskih biblioteka – ISPRAVLJENO.

POPRAVAK verifikacije (``verify``):

* allowlista algoritma – prihvaća se SAMO ``HS256`` (``none`` i ostalo se odbija),
* potpis se uspoređuje u konstantnom vremenu (``hmac.compare_digest``),
* provjerava se ``exp`` (istekli token se odbija),
* tajna je jaka (256 bita) i dolazi iz okoline ``LAB12_JWT_SECRET`` (vidi config.py).

U stvarnim projektima koristite provjerenu biblioteku (PyJWT, joserfc, Authlib) i eksplicitno
zadajte dopuštene algoritme, npr. ``jwt.decode(token, key, algorithms=["HS256"])``, te po
potrebi provjeru ``iss`` i ``aud``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime

ALLOWED_ALGORITHM = "HS256"


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def hmac_sha256(message: str, key: bytes) -> bytes:
    return hmac.new(key, message.encode("ascii"), hashlib.sha256).digest()


class JwtService:
    def __init__(self, secret: str | bytes) -> None:
        self._secret = secret.encode("utf-8") if isinstance(secret, str) else secret

    def create_token(self, username: str, role: str, expires_at: datetime) -> str:
        """Izrađuje HS256 token s proizvoljnim vremenom isteka (korisno i za testove)."""
        header = {"alg": ALLOWED_ALGORITHM, "typ": "JWT"}
        payload = {
            "sub": username,
            "role": role,
            "iat": int(datetime.now(UTC).timestamp()),
            "exp": int(expires_at.timestamp()),
        }
        signing_input = (
            b64url_encode(json.dumps(header, separators=(",", ":")).encode())
            + "."
            + b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        )
        signature = b64url_encode(hmac_sha256(signing_input, self._secret))
        return signing_input + "." + signature

    def verify(self, token: str) -> dict | None:
        """Vraća claimove (sub, role ...) ili None ako token nije valjan."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            header = json.loads(b64url_decode(parts[0]))
            payload = json.loads(b64url_decode(parts[1]))
            if not isinstance(header, dict) or not isinstance(payload, dict):
                return None
            # POPRAVAK: algoritam određuje POSLUŽITELJ (allowlista), a ne zaglavlje tokena.
            if header.get("alg") != ALLOWED_ALGORITHM:
                return None
            expected = b64url_encode(hmac_sha256(parts[0] + "." + parts[1], self._secret))
            # POPRAVAK: usporedba u konstantnom vremenu.
            if not hmac.compare_digest(expected.encode("ascii"), parts[2].encode("ascii")):
                return None
            # POPRAVAK: provjera isteka (exp je obavezan).
            exp = payload.get("exp")
            if not isinstance(exp, int | float) or exp <= datetime.now(UTC).timestamp():
                return None
            return payload
        except (ValueError, UnicodeDecodeError, UnicodeEncodeError, AttributeError):
            return None
