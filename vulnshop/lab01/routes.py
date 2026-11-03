"""Lab01 – A01 Broken Access Control: IDOR (CWE-639) – ISPRAVLJENO.

POPRAVAK: nakon dohvata narudžbe provjerava se vlasništvo. Ako narudžba nije korisnikova, a
korisnik nije ADMIN, vraća se 404 (ne 403) – tako ne otkrivamo ni postojanje tuđe narudžbe.
"""

from fastapi import APIRouter

from vulnshop.common.auth import CurrentUserDep, DbDep
from vulnshop.common.db import to_money
from vulnshop.common.http import error

router = APIRouter(tags=["Lab01 – IDOR"])


@router.get("/api/lab01/orders/{order_id}")
def get_order(order_id: int, user: CurrentUserDep, db: DbDep):
    row = db.query_one(
        "SELECT id, owner_username, items, shipping_address, total FROM lab01_orders WHERE id = ?",
        (order_id,),
    )
    # POPRAVAK: provjera vlasništva. Tuđa narudžba izgleda isto kao nepostojeća (404),
    # osim za administratora koji smije vidjeti sve narudžbe.
    if row is None or (row["owner_username"] != user.username and not user.is_admin):
        return error(404, "Narudžba nije pronađena.")
    return to_dto(row)


def to_dto(row: dict) -> dict:
    return {
        "id": row["id"],
        "owner": row["owner_username"],
        "items": row["items"],
        "shippingAddress": row["shipping_address"],
        "total": to_money(row["total"]),
    }
