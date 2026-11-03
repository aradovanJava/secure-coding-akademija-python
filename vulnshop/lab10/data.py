"""Lab10 – novčanici (svatko 1000.00 EUR), proizvodi i evidencija iskorištenih kupona."""

from fastapi import FastAPI


def init(app: FastAPI) -> None:
    app.state.db.executescript(
        """
        CREATE TABLE lab10_wallets (
            username TEXT PRIMARY KEY,
            balance  NUMERIC NOT NULL
        );
        INSERT INTO lab10_wallets VALUES ('ana',   '1000.00');
        INSERT INTO lab10_wallets VALUES ('marko', '1000.00');
        INSERT INTO lab10_wallets VALUES ('admin', '1000.00');

        CREATE TABLE lab10_products (
            id    INTEGER PRIMARY KEY,
            name  TEXT    NOT NULL,
            price NUMERIC NOT NULL
        );
        INSERT INTO lab10_products VALUES (1, 'Laptop',    '899.00');
        INSERT INTO lab10_products VALUES (2, 'Slušalice', '99.00');
        INSERT INTO lab10_products VALUES (3, 'Kabel',     '9.99');

        CREATE TABLE lab10_coupon_usage (
            username TEXT NOT NULL,
            coupon   TEXT NOT NULL
        );
        """
    )
