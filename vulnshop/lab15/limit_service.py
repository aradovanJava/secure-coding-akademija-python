"""Lab15 – servis koji provjerava pravila transakcije (valuta, iznos, dnevni limit).

Baca iznimku za nepoznatu valutu, neispravan iznos ili prekoračen limit. Poanta vježbe je da
RANJIVI endpoint ovu iznimku "proguta" (fail-open) umjesto da odbije transakciju.
"""

from decimal import Decimal


class LimitExceededError(Exception):
    """Iznos premašuje dnevni limit."""


class LimitService:
    ALLOWED_CURRENCIES = frozenset({"EUR", "USD"})
    DAILY_LIMIT = Decimal("1000.00")

    def check(self, amount: Decimal, currency: str | None) -> None:
        """Provjerava je li transfer unutar dopuštenih pravila.

        :raises ValueError: nepoznata valuta ili neispravan iznos
        :raises LimitExceededError: iznos premašuje dnevni limit
        """
        if currency not in self.ALLOWED_CURRENCIES:
            raise ValueError(f"Nepoznata valuta: {currency}")
        if amount is None or amount <= 0:
            raise ValueError(f"Neispravan iznos: {amount}")
        if amount > self.DAILY_LIMIT:
            raise LimitExceededError(f"Prekoračen dnevni limit od {self.DAILY_LIMIT} EUR.")
