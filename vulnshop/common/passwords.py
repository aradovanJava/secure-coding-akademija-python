"""Sigurna pohrana lozinki (zajednički dio, nije vježba).

Koristi se Argon2id (biblioteka argon2-cffi) – OWASP-ova prva preporuka za pohranu lozinki.
Hash sadrži sol i parametre, pa iste lozinke daju različite hasheve.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
