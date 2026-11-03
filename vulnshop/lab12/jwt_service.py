"""Lab12 – ručna implementacija JWT-a (HS256) bez vanjskih biblioteka.

RANJIVA verifikacija (``verify``):

* čita ``alg`` iz zaglavlja tokena – ako je ``none``, preskače provjeru potpisa,
* ne provjerava ``exp`` (istekli token prolazi),
* potpis uspoređuje operatorom ``==`` (vrijeme usporedbe ovisi o sadržaju).

Tajna je slaba i hardkodirana (``secret123``, vidi config.py).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime


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
        header = {"alg": "HS256", "typ": "JWT"}
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
        """RANJIVO: vraća claimove (sub, role ...) ili None ako token nije valjan."""
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return None
            header = json.loads(b64url_decode(parts[0]))
            payload = json.loads(b64url_decode(parts[1]))
            if not isinstance(header, dict) or not isinstance(payload, dict):
                return None
            # RANJIVO: algoritam određuje napadač – "none" preskače provjeru potpisa.
            if str(header.get("alg", "")).lower() != "none":
                if len(parts) != 3:
                    return None
                expected = b64url_encode(hmac_sha256(parts[0] + "." + parts[1], self._secret))
                # RANJIVO: obična usporedba stringova (nije u konstantnom vremenu).
                if expected != parts[2]:
                    return None
            # RANJIVO: exp se ne provjerava.
            return payload
        except (ValueError, UnicodeDecodeError, AttributeError):
            return None
