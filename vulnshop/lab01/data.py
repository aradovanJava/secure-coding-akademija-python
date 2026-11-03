"""Lab01 – tablica narudžbi i početni podaci (1001, 1002 = ana; 1003 = marko; 1004 = admin)."""

from fastapi import FastAPI


def init(app: FastAPI) -> None:
    db = app.state.db
    db.executescript(
        """
        CREATE TABLE lab01_orders (
            id               INTEGER PRIMARY KEY,
            owner_username   TEXT    NOT NULL,
            items            TEXT    NOT NULL,
            shipping_address TEXT    NOT NULL,
            total            NUMERIC NOT NULL
        );
        INSERT INTO lab01_orders VALUES (1001, 'ana',   'Laptop, Miš', 'Ilica 1, Zagreb',       '999.00');
        INSERT INTO lab01_orders VALUES (1002, 'ana',   'Tipkovnica',  'Ilica 1, Zagreb',       '49.00');
        INSERT INTO lab01_orders VALUES (1003, 'marko', 'Monitor',     'Savska 10, Zagreb',     '299.00');
        INSERT INTO lab01_orders VALUES (1004, 'admin', 'Server',      'Koturaška 47, Zagreb',  '4999.00');
        """
    )
