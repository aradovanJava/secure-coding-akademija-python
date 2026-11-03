"""Zajednička tablica korisnika i početni podaci (nije vježba).

Seed korisnici (isti u Java i .NET verziji):
    ana / Ana123! (USER), marko / Marko123! (USER), admin / Admin123! (ADMIN)
Lozinke se pohranjuju kao Argon2id hash (vidi passwords.py).
"""

from __future__ import annotations

from vulnshop.common.db import Database
from vulnshop.common.passwords import hash_password

SEED_USERS = [
    (1, "ana", "Ana123!", "USER"),
    (2, "marko", "Marko123!", "USER"),
    (3, "admin", "Admin123!", "ADMIN"),
]


def init_users(db: Database) -> None:
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role     TEXT NOT NULL
        );
        """
    )
    for user_id, username, password, role in SEED_USERS:
        db.execute(
            "INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)",
            (user_id, username, hash_password(password), role),
        )
