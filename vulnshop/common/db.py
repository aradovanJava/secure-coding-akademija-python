"""Jednostavan sloj za rad sa SQLite bazom u memoriji (zajednički dio, nije vježba).

Svaka instanca aplikacije (i svaki testni klijent) dobiva vlastitu, svježu bazu.
Upiti se uvijek šalju s parametrima (``?``) – osim tamo gdje vježba namjerno pokazuje
suprotno (Lab07).
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from decimal import Decimal
from typing import Any

# Iznosi (Decimal) zapisuju se kao tekst kako se ne bi gubila preciznost.
sqlite3.register_adapter(Decimal, str)

CENT = Decimal("0.01")


def to_money(value: Any) -> Decimal:
    """Pretvara vrijednost iz baze u iznos s dvije decimale."""
    return Decimal(str(value)).quantize(CENT)


class Database:
    """Omotač oko jedne SQLite veze u memoriji (sigurno za više dretvi zahvaljujući bravi)."""

    def __init__(self) -> None:
        # isolation_level=None -> autocommit; transakcije se otvaraju eksplicitno (transaction()).
        self._conn = sqlite3.connect(":memory:", check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()

    def executescript(self, script: str) -> None:
        with self._lock:
            self._conn.executescript(script)

    def execute(self, sql: str, params: Sequence[Any] = ()) -> int:
        """Izvršava INSERT/UPDATE/DELETE i vraća broj promijenjenih redaka."""
        with self._lock:
            return self._conn.execute(sql, params).rowcount

    def insert(self, sql: str, params: Sequence[Any] = ()) -> int:
        """Izvršava INSERT i vraća id novog retka."""
        with self._lock:
            return int(self._conn.execute(sql, params).lastrowid)

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(row) for row in self._conn.execute(sql, params).fetchall()]

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> dict[str, Any] | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    @contextmanager
    def transaction(self) -> Iterator[Database]:
        """Sve naredbe unutar bloka ``with`` izvršavaju se kao jedna transakcija.

        Ako se u bloku dogodi iznimka, promjene se poništavaju (ROLLBACK).
        """
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                yield self
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")
