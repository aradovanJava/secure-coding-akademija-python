"""Lab11 – A07 Authentication Failures: brute force i enumeracija korisnika (CWE-307, CWE-204).

RANJIVO: različiti odgovori za nepostojećeg korisnika (404 "Korisnik ne postoji.") i pogrešnu
lozinku (401 "Pogrešna lozinka.") omogućuju enumeraciju korisničkih imena. Broj pokušaja nije
ograničen, pa je moguć neometan brute force napad rječnikom lozinki.
"""

from fastapi import APIRouter
from pydantic import BaseModel

from vulnshop.common.auth import DbDep
from vulnshop.common.http import error
from vulnshop.common.passwords import verify_password

router = APIRouter(tags=["Lab11 – Brute force i enumeracija"])


class LoginRequest(BaseModel):
    username: str | None = None
    password: str | None = None


@router.post("/api/lab11/login")
def login(body: LoginRequest, db: DbDep):
    username = body.username or ""
    password = body.password or ""
    row = db.query_one("SELECT password_hash FROM lab11_users WHERE username = ?", (username,))
    # RANJIVO: posebna poruka i status za nepostojećeg korisnika omogućuju enumeraciju.
    if row is None:
        return error(404, "Korisnik ne postoji.")
    # RANJIVO: nema brojača neuspjelih pokušaja ni zaključavanja računa.
    if not verify_password(row["password_hash"], password):
        return error(401, "Pogrešna lozinka.")
    return {"status": "prijavljen", "username": username}
