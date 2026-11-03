"""Lab10 – A06 Insecure Design: poslovna logika (CWE-840, CWE-20).

RANJIVO: poslužitelj vjeruje cijeni (``unitPrice``) i količini (``quantity``) iz zahtjeva
(dopušta i negativne), primjenjuje SVAKI kupon iz liste (pa i isti više puta) i mijenja stanje
novčanika bez ikakve provjere. Negativna količina tako POVEĆAVA stanje, a ponavljanjem kupona
iznos se umjetno obara.
"""

from decimal import ROUND_HALF_UP, Decimal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from vulnshop.common.auth import CurrentUserDep, DbDep
from vulnshop.common.db import CENT, to_money

router = APIRouter(tags=["Lab10 – Nesiguran dizajn"])

COUPON_CODE = "AKADEMIJA10"
COUPON_FACTOR = Decimal("0.90")


class CheckoutItem(BaseModel):
    product_id: int = Field(alias="productId")
    quantity: int
    # RANJIVO: cijenu određuje klijent.
    unit_price: Decimal = Field(alias="unitPrice")


class CheckoutRequest(BaseModel):
    items: list[CheckoutItem]
    coupon_codes: list[str] | None = Field(default=None, alias="couponCodes")


@router.get("/api/lab10/wallet")
def wallet(user: CurrentUserDep, db: DbDep):
    row = db.query_one("SELECT balance FROM lab10_wallets WHERE username = ?", (user.username,))
    return {"username": user.username, "balance": to_money(row["balance"])}


@router.post("/api/lab10/checkout")
def checkout(body: CheckoutRequest, user: CurrentUserDep, db: DbDep):
    total = Decimal("0")
    # RANJIVO: koriste se unitPrice i quantity iz zahtjeva (bez provjere predznaka i raspona).
    for item in body.items:
        total += item.unit_price * item.quantity
    # RANJIVO: svaki kupon iz liste primjenjuje se zasebno (može i više puta isti).
    for coupon in body.coupon_codes or []:
        if coupon.upper() == COUPON_CODE:
            total *= COUPON_FACTOR
    total = total.quantize(CENT, rounding=ROUND_HALF_UP)

    row = db.query_one("SELECT balance FROM lab10_wallets WHERE username = ?", (user.username,))
    balance = to_money(row["balance"])
    # RANJIVO: nema provjere total > 0 ni dostatnog stanja; negativan total povećava stanje.
    new_balance = balance - total
    db.execute("UPDATE lab10_wallets SET balance = ? WHERE username = ?", (new_balance, user.username))
    return {"charged": total, "balance": new_balance}
