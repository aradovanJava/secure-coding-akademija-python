"""Lab07 – A05 Injection: SQL injection (CWE-89) – ISPRAVLJENO.

POPRAVAK: svi upiti su PARAMETRIZIRANI – korisnički unos šalje se bazi kao parametar (``?``),
a ne kao dio teksta SQL naredbe, pa ga baza nikad ne tumači kao SQL. Za LIKE se dodatno
"escapeaju" zamjenski znakovi % i _, a duljina unosa je ograničena.

Dodatno (obrana u dubinu): ORM (npr. SQLAlchemy) parametrizira upite automatski, a aplikacija
se na bazu spaja korisnikom s najmanjim potrebnim ovlastima.
"""

from fastapi import APIRouter
from pydantic import BaseModel

from vulnshop.common.auth import DbDep
from vulnshop.common.db import to_money
from vulnshop.common.http import error

router = APIRouter(tags=["Lab07 – SQL injection"])

MAX_QUERY_LENGTH = 100


def escape_like(value: str) -> str:
    """Zamjenski znakovi LIKE-a (% i _) tretiraju se doslovno."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@router.get("/api/lab07/products/search")
def search_products(q: str, db: DbDep):
    if len(q) > MAX_QUERY_LENGTH:
        return error(400, "Pojam za pretragu je predugačak.")
    # POPRAVAK: parametrizirani upit + escape za LIKE.
    rows = db.query(
        "SELECT id, name, description, price FROM lab07_products WHERE hidden = 0 AND name LIKE ? ESCAPE '\\'",
        (f"%{escape_like(q)}%",),
    )
    return [{**row, "price": to_money(row["price"])} for row in rows]


class LoginRequest(BaseModel):
    username: str | None = None
    password: str | None = None


@router.post("/api/lab07/login")
def login(body: LoginRequest, db: DbDep):
    # POPRAVAK: parametrizirani upit (lozinke u čistom tekstu ostaju samo radi vježbe – vidi Lab06).
    row = db.query_one(
        "SELECT id, username FROM lab07_accounts WHERE username = ? AND password = ?",
        (body.username or "", body.password or ""),
    )
    if row is None:
        return error(401, "Neispravni podaci.")
    return {"status": "prijavljen", "username": row["username"]}
