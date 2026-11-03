"""Lab15 – bankovni računi (HR-ANA-001, HR-MARKO-001, HR-ADMIN-001)."""

from fastapi import FastAPI


def init(app: FastAPI) -> None:
    app.state.db.executescript(
        """
        CREATE TABLE lab15_accounts (
            account_no     TEXT    PRIMARY KEY,
            owner_username TEXT    NOT NULL,
            balance        NUMERIC NOT NULL
        );
        INSERT INTO lab15_accounts VALUES ('HR-ANA-001',   'ana',   '5000.00');
        INSERT INTO lab15_accounts VALUES ('HR-MARKO-001', 'marko', '1000.00');
        INSERT INTO lab15_accounts VALUES ('HR-ADMIN-001', 'admin', '10000.00');
        """
    )
