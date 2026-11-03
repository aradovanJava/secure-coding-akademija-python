"""Lab15 – A10 Mishandling of Exceptional Conditions (CWE-636, CWE-755, CWE-209, CWE-460).

RANJIVO:

1. FAIL-OPEN: iznimka iz ``LimitService.check`` hvata se i ignorira, pa transfer s nepoznatom
   valutom (npr. ``XYZ``) i iznosom iznad limita prolazi.
2. NEMA TRANSAKCIJE: terećenje se izvrši, a ako odobrenje (uplata na nepostojeći račun) ne
   uspije, novac nestaje.
3. Poruka greške vraća naziv klase iznimke i detalje (procurivanje informacija).
"""

import logging
from decimal import Decimal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from vulnshop.common.auth import CurrentUserDep, DbDep
from vulnshop.common.db import to_money
from vulnshop.common.http import error
from vulnshop.lab15.limit_service import LimitService

router = APIRouter(tags=["Lab15 – Rukovanje iznimkama"])

log = logging.getLogger("vulnshop.lab15")
limit_service = LimitService()


class TransferRequest(BaseModel):
    from_account: str | None = Field(default=None, alias="fromAccount")
    to_account: str | None = Field(default=None, alias="toAccount")
    amount: str | None = None
    currency: str | None = None


@router.get("/api/lab15/accounts")
def accounts(user: CurrentUserDep, db: DbDep):
    rows = db.query(
        "SELECT account_no, balance FROM lab15_accounts WHERE owner_username = ? ORDER BY account_no",
        (user.username,),
    )
    return [{"accountNo": row["account_no"], "balance": to_money(row["balance"])} for row in rows]


@router.post("/api/lab15/transfer")
def transfer(body: TransferRequest, user: CurrentUserDep, db: DbDep):
    try:
        amount = Decimal(body.amount)
        # RANJIVO (1) FAIL-OPEN: iznimka u sigurnosnoj provjeri se "proguta".
        try:
            limit_service.check(amount, body.currency)
        except Exception as exc:
            log.debug("Provjera limita nije uspjela, nastavljam svejedno: %s", exc)

        # RANJIVO (2): terećenje i odobrenje izvršavaju se bez transakcije.
        db.execute("UPDATE lab15_accounts SET balance = balance - ? WHERE account_no = ?", (amount, body.from_account))
        updated = db.execute(
            "UPDATE lab15_accounts SET balance = balance + ? WHERE account_no = ?", (amount, body.to_account)
        )
        if updated == 0:
            # Odredišni račun ne postoji -> terećenje se NE poništava, novac "nestaje".
            raise LookupError(
                f"Odredišni račun {body.to_account} ne postoji u tablici lab15_accounts "
                "(UPDATE lab15_accounts SET balance = balance + ? WHERE account_no = ?)"
            )
        return {"status": "izvršeno", "amount": amount}
    except Exception as exc:
        # RANJIVO (3): vraća se puni naziv klase iznimke i detaljna poruka (s nazivom tablice i SQL-om).
        return error(500, f"{type(exc).__module__}.{type(exc).__qualname__}: {exc}")
