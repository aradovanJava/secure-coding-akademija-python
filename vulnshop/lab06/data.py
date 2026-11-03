"""Lab06 – kupci (dio A, lozinke) i kartice (dio B, šifriranje).

Seed kupci imaju slabe lozinke iz ``wordlists/top-100.txt``; maja i ivan imaju ISTU lozinku.
Hashevi se računaju funkcijom ``hash_password`` iz routes.py – kad je ispravite, i seed se
automatski hashira novom metodom.
"""

from fastapi import FastAPI

from vulnshop.lab06.routes import hash_password

SEED_CUSTOMERS = [("ivan", "123456"), ("petra", "password"), ("luka", "qwerty"), ("maja", "123456")]


def init(app: FastAPI) -> None:
    db = app.state.db
    db.executescript(
        """
        CREATE TABLE lab06_customers (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE lab06_cards (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            owner      TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            last4      TEXT NOT NULL
        );
        """
    )
    for username, password in SEED_CUSTOMERS:
        db.execute(
            "INSERT INTO lab06_customers (username, password_hash) VALUES (?, ?)",
            (username, hash_password(password)),
        )
