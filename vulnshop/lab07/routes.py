"""Lab07 – A05 Injection: SQL injection (CWE-89).

RANJIVO: i pretraga proizvoda i prijava grade SQL upit spajanjem stringova s korisničkim
unosom (f-string). Napadač može dohvatiti skrivene proizvode (``' OR '1'='1' --``), izvući
podatke drugih tablica (UNION) ili zaobići prijavu (``admin'--``).
"""

import sqlite3

from fastapi import APIRouter
from pydantic import BaseModel

from vulnshop.common.auth import DbDep
from vulnshop.common.db import to_money
from vulnshop.common.http import error

router = APIRouter(tags=["Lab07 – SQL injection"])


@router.get("/api/lab07/products/search")
def search_products(q: str, db: DbDep):
    # RANJIVO: q se umeće izravno u tekst SQL upita.
    sql = f"SELECT id, name, description, price FROM lab07_products WHERE hidden = 0 AND name LIKE '%{q}%'"
    try:
        rows = db.query(sql)
    except sqlite3.Error:
        return error(400, "Greška u upitu.")
    return [{**row, "price": to_money(row["price"])} for row in rows]


class LoginRequest(BaseModel):
    username: str | None = None
    password: str | None = None


@router.post("/api/lab07/login")
def login(body: LoginRequest, db: DbDep):
    username = body.username or ""
    password = body.password or ""
    # RANJIVO: korisničko ime i lozinka umeću se izravno u SQL.
    sql = f"SELECT id, username FROM lab07_accounts WHERE username = '{username}' AND password = '{password}'"
    try:
        row = db.query_one(sql)
    except sqlite3.Error:
        return error(401, "Neispravni podaci.")
    if row is None:
        return error(401, "Neispravni podaci.")
    return {"status": "prijavljen", "username": row["username"]}
