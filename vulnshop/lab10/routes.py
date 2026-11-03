"""Lab10 – A06 Insecure Design: poslovna logika (CWE-840, CWE-20) – ISPRAVLJENO.

POPRAVAK (poslovna pravila provode se na POSLUŽITELJU):

* cijena se UVIJEK uzima iz baze – ``unitPrice`` iz zahtjeva se ignorira,
* količina mora biti od 1 do 10,
* najviše jedan kupon, i to jednokratno po korisniku,
* ukupni iznos mora biti veći od 0 i stanje novčanika mora biti dostatno,
* cijela operacija izvršava se u jednoj transakciji.
"""

from decimal import ROUND_HALF_UP, Decimal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from vulnshop.common.auth import CurrentUserDep, DbDep
from vulnshop.common.db import CENT, to_money
from vulnshop.common.http import error

router = APIRouter(tags=["Lab10 – Nesiguran dizajn"])

COUPON_CODE = "AKADEMIJA10"
COUPON_FACTOR = Decimal("0.90")


class CheckoutItem(BaseModel):
    product_id: int = Field(alias="productId")
    # POPRAVAK: količina 1..10 (validira Pydantic; neispravno -> 400).
    quantity: int = Field(ge=1, le=10)
    # Polje se i dalje smije poslati (kompatibilnost klijenata), ali se IGNORIRA.
    unit_price: Decimal | None = Field(default=None, alias="unitPrice")


class CheckoutRequest(BaseModel):
    items: list[CheckoutItem] = Field(min_length=1)
    coupon_codes: list[str] | None = Field(default=None, alias="couponCodes")


@router.get("/api/lab10/wallet")
def wallet(user: CurrentUserDep, db: DbDep):
    row = db.query_one("SELECT balance FROM lab10_wallets WHERE username = ?", (user.username,))
    return {"username": user.username, "balance": to_money(row["balance"])}


class CheckoutRejected(Exception):
    """Narudžba krši poslovno pravilo (vraća se 400)."""


@router.post("/api/lab10/checkout")
def checkout(body: CheckoutRequest, user: CurrentUserDep, db: DbDep):
    coupons = body.coupon_codes or []
    if len(coupons) > 1:
        return error(400, "Dopušten je najviše jedan kupon.")
    try:
        # POPRAVAK: sve provjere i promjene stanja u jednoj transakciji.
        with db.transaction():
            total = Decimal("0")
            for item in body.items:
                product = db.query_one("SELECT price FROM lab10_products WHERE id = ?", (item.product_id,))
                if product is None:
                    raise CheckoutRejected("Nepostojeći proizvod.")
                # POPRAVAK: cijena iz baze, NE iz zahtjeva.
                total += to_money(product["price"]) * item.quantity

            if coupons:
                if coupons[0].upper() != COUPON_CODE:
                    raise CheckoutRejected("Nepoznat kupon.")
                used = db.query_one(
                    "SELECT 1 FROM lab10_coupon_usage WHERE username = ? AND coupon = ?", (user.username, COUPON_CODE)
                )
                if used:
                    raise CheckoutRejected("Kupon je već iskorišten.")
                total *= COUPON_FACTOR
                db.execute(
                    "INSERT INTO lab10_coupon_usage (username, coupon) VALUES (?, ?)", (user.username, COUPON_CODE)
                )

            total = total.quantize(CENT, rounding=ROUND_HALF_UP)
            if total <= 0:
                raise CheckoutRejected("Neispravan ukupni iznos.")

            row = db.query_one("SELECT balance FROM lab10_wallets WHERE username = ?", (user.username,))
            balance = to_money(row["balance"])
            # POPRAVAK: provjera dostatnog stanja.
            if balance < total:
                raise CheckoutRejected("Nedovoljno sredstava.")
            new_balance = balance - total
            db.execute("UPDATE lab10_wallets SET balance = ? WHERE username = ?", (new_balance, user.username))
    except CheckoutRejected as exc:
        # Iznimka unutar bloka transaction() poništava sve promjene (ROLLBACK).
        return error(400, str(exc))
    return {"charged": total, "balance": new_balance}
