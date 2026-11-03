"""Lab13 – klase košarice i "gadget" klasa.

``Cart`` i ``CartItem`` su legitimne klase koje klijent šalje serijalizirane modulom pickle.
Same po sebi nisu opasne – problem je u tome što ``pickle.loads`` može stvoriti objekt BILO
KOJE klase (i pozvati bilo koju funkciju), a ne samo košaricu.
"""

from __future__ import annotations

from pathlib import Path


class CartItem:
    """Legitimna stavka košarice (naziv proizvoda i količina)."""

    def __init__(self, product_name: str, quantity: int) -> None:
        self.product_name = product_name
        self.quantity = quantity


class Cart:
    """Legitimna košarica."""

    def __init__(self, items: list[CartItem] | None = None) -> None:
        self.items: list[CartItem] = list(items or [])


class DiagnosticsTask:
    """ "Gadget" klasa – simulira stvarne gadget lance u bibliotekama.

    Metoda ``__setstate__`` izvršava se AUTOMATSKI tijekom ``pickle.loads()``, prije nego što
    aplikacija uopće vidi objekt. Ovdje zapisuje ``content`` u datoteku ``report_path``
    (proizvoljan zapis datoteke) – dovoljan dokaz da je napadač preuzeo kontrolu nad izvršavanjem.

    Napomena: u Pythonu napadaču gadget klasa zapravo NIJE ni potrebna – metodom
    ``__reduce__`` pickle može pozvati bilo koju funkciju (npr. ``os.system``). Ova klasa
    postoji samo zato da vježba bude bezopasna (zapisuje samo tekstualnu datoteku).
    """

    def __init__(self, report_path: str, content: str) -> None:
        self.report_path = report_path
        self.content = content

    def __setstate__(self, state: dict) -> None:
        self.__dict__.update(state)
        # RANJIVO (gadget): izvršava se tijekom deserijalizacije.
        if self.report_path and self.content:
            Path(self.report_path).write_text(self.content, encoding="utf-8")
