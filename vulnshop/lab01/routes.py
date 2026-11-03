"""Lab01 – A01 Broken Access Control: IDOR (CWE-639).

RANJIVO: endpoint vraća narudžbu isključivo prema identifikatoru iz URL-a i ne provjerava
pripada li narudžba prijavljenom korisniku. Identifikatori su redni brojevi, pa prijavljeni
korisnik jednostavno mijenja broj u URL-u i čita tuđe narudžbe.
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
    if row is None:
        return error(404, "Narudžba nije pronađena.")
    # RANJIVO: ne provjerava se je li prijavljeni korisnik vlasnik narudžbe niti je li ADMIN.
    return to_dto(row)


def to_dto(row: dict) -> dict:
    return {
        "id": row["id"],
        "owner": row["owner_username"],
        "items": row["items"],
        "shippingAddress": row["shipping_address"],
        "total": to_money(row["total"]),
    }
