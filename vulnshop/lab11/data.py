"""Lab11 – korisnici za vježbu brute force napada i enumeracije.

* ivana / sunshine1 – lozinka se nalazi u wordlists/top-100.txt (brute force demo),
* tomislav / T0m!slav#2026 – jaka lozinka,
* lockme / Lock!Me2026 – zaseban korisnik za test zaključavanja računa.
"""

from fastapi import FastAPI

from vulnshop.common.passwords import hash_password

SEED_USERS = [(1, "ivana", "sunshine1"), (2, "tomislav", "T0m!slav#2026"), (3, "lockme", "Lock!Me2026")]


def init(app: FastAPI) -> None:
    db = app.state.db
    db.executescript(
        """
        CREATE TABLE lab11_users (
            id            INTEGER PRIMARY KEY,
            username      TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        );
        """
    )
    for user_id, username, password in SEED_USERS:
        db.execute(
            "INSERT INTO lab11_users (id, username, password_hash) VALUES (?, ?, ?)",
            (user_id, username, hash_password(password)),
        )
