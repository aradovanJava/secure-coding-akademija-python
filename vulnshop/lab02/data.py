"""Lab02 – tablica profila (uloga u profilu određuje pristup admin/users)."""

from fastapi import FastAPI


def init(app: FastAPI) -> None:
    app.state.db.executescript(
        """
        CREATE TABLE lab02_profiles (
            user_id      INTEGER PRIMARY KEY,
            display_name TEXT NOT NULL,
            email        TEXT NOT NULL,
            role         TEXT NOT NULL
        );
        INSERT INTO lab02_profiles VALUES (1, 'Ana Anić',      'ana@akademija.hr',   'USER');
        INSERT INTO lab02_profiles VALUES (2, 'Marko Marić',   'marko@akademija.hr', 'USER');
        INSERT INTO lab02_profiles VALUES (3, 'Administrator', 'admin@akademija.hr', 'ADMIN');
        """
    )
