"""Lab08 – pohranjene recenzije proizvoda."""

from fastapi import FastAPI


def init(app: FastAPI) -> None:
    app.state.db.executescript(
        """
        CREATE TABLE lab08_reviews (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            author     TEXT    NOT NULL,
            text       TEXT    NOT NULL
        );
        INSERT INTO lab08_reviews (product_id, author, text) VALUES (1, 'Ana', 'Odličan laptop, preporučujem!');
        """
    )
