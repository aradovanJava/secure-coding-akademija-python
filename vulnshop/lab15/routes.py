"""Lab15 – A10 Mishandling of Exceptional Conditions (CWE-636, CWE-755, CWE-209, CWE-460) – ISPRAVLJENO.

POPRAVAK:

1. FAIL-CLOSED: svaka iznimka u sigurnosnoj provjeri (``LimitService.check``) znači ODBIJANJE.
2. Validacija ulaza unaprijed: iznos kao ``Decimal`` (> 0, najviše 2 decimale), valuta s popisa,
   izvorišni račun mora pripadati prijavljenom korisniku i imati dovoljno sredstava.
3. TRANSAKCIJA: terećenje i odobrenje izvršavaju se zajedno – ako odobrenje ne uspije
   (nepostojeći račun), terećenje se poništava (ROLLBACK).
4. Generičke poruke greške bez naziva klasa, tablica i SQL-a; detalji idu samo u log, uz
   korelacijski ID koji korisnik može navesti podršci.
"""

import logging
import uuid
from decimal import Decimal, InvalidOperation

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from vulnshop.common.auth import CurrentUserDep, DbDep
from vulnshop.common.db import to_money
from vulnshop.lab15.limit_service import LimitService

router = APIRouter(tags=["Lab15 – Rukovanje iznimkama"])

log = logging.getLogger("vulnshop.lab15")
limit_service = LimitService()


class TransferRequest(BaseModel):
    from_account: str | None = Field(default=None, alias="fromAccount")
    to_account: str | None = Field(default=None, alias="toAccount")
    amount: str | None = None
    currency: str | None = None


class TransferRejected(Exception):
    """Transfer se odbija (vraća se 400 s generičkom porukom)."""


@router.get("/api/lab15/accounts")
def accounts(user: CurrentUserDep, db: DbDep):
    rows = db.query(
        "SELECT account_no, balance FROM lab15_accounts WHERE owner_username = ? ORDER BY account_no",
        (user.username,),
    )
    return [{"accountNo": row["account_no"], "balance": to_money(row["balance"])} for row in rows]


def parse_amount(value: str | None) -> Decimal:
    try:
        amount = Decimal(value or "")
    except InvalidOperation as exc:
        raise TransferRejected("Neispravan iznos.") from exc
    if not amount.is_finite() or amount <= 0 or amount != amount.quantize(Decimal("0.01")):
        raise TransferRejected("Neispravan iznos.")
    return amount


@router.post("/api/lab15/transfer")
def transfer(body: TransferRequest, user: CurrentUserDep, db: DbDep):
    correlation_id = str(uuid.uuid4())
    try:
        # POPRAVAK (2): validacija ulaza unaprijed.
        amount = parse_amount(body.amount)
        if not body.from_account or not body.to_account or body.from_account == body.to_account:
            raise TransferRejected("Neispravni podaci o računima.")

        # POPRAVAK (1): FAIL-CLOSED – bilo koja iznimka u provjeri znači odbijanje.
        try:
            limit_service.check(amount, body.currency)
        except Exception as exc:
            log.warning("Transfer odbijen (provjera limita) correlationId=%s razlog=%s", correlation_id, exc)
            raise TransferRejected("Transfer nije dopušten.") from exc

        # POPRAVAK (3): sve unutar jedne transakcije.
        with db.transaction():
            source = db.query_one(
                "SELECT balance FROM lab15_accounts WHERE account_no = ? AND owner_username = ?",
                (body.from_account, user.username),
            )
            if source is None:
                raise TransferRejected("Izvorišni račun nije dostupan.")
            if to_money(source["balance"]) < amount:
                raise TransferRejected("Nedovoljno sredstava.")
            db.execute(
                "UPDATE lab15_accounts SET balance = balance - ? WHERE account_no = ?", (amount, body.from_account)
            )
            updated = db.execute(
                "UPDATE lab15_accounts SET balance = balance + ? WHERE account_no = ?", (amount, body.to_account)
            )
            if updated == 0:
                # Iznimka unutar transakcije -> ROLLBACK poništava i terećenje.
                raise TransferRejected("Transfer nije moguće izvršiti.")
    except TransferRejected as exc:
        # POPRAVAK (4): generička poruka + korelacijski ID, bez tehničkih detalja.
        return JSONResponse(status_code=400, content={"error": str(exc), "correlationId": correlation_id})
    return {"status": "izvršeno", "amount": amount}
