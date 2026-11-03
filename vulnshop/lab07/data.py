"""Lab07 – proizvodi (jedan skriveni) i računi s lozinkama u čistom tekstu (NAMJERNO, za UNION napad)."""

from fastapi import FastAPI


def init(app: FastAPI) -> None:
    app.state.db.executescript(
        """
        CREATE TABLE lab07_products (
            id          INTEGER PRIMARY KEY,
            name        TEXT    NOT NULL,
            description TEXT    NOT NULL,
            price       NUMERIC NOT NULL,
            hidden      INTEGER NOT NULL
        );
        INSERT INTO lab07_products VALUES (1, 'Laptop',             'Prijenosno računalo',    '899.00', 0);
        INSERT INTO lab07_products VALUES (2, 'Miš',                'Optički miš',            '19.00',  0);
        INSERT INTO lab07_products VALUES (3, 'Tipkovnica',         'Mehanička tipkovnica',   '79.00',  0);
        INSERT INTO lab07_products VALUES (4, 'Monitor',            '27-inčni monitor',       '299.00', 0);
        INSERT INTO lab07_products VALUES (5, 'Interni prototip X', 'Tajni interni proizvod', '0.00',   1);

        CREATE TABLE lab07_accounts (
            id       INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        );
        INSERT INTO lab07_accounts VALUES (1, 'admin',   'SuperTajna2026');
        INSERT INTO lab07_accounts VALUES (2, 'webshop', 'Shop!2026');
        """
    )
