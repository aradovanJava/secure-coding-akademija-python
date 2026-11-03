"""Lab02 – A01 Broken Access Control: mass assignment / eskalacija privilegija (CWE-915, CWE-269) – ISPRAVLJENO.

POPRAVAK: ``PUT /api/lab02/profile`` prima DTO koji sadrži SAMO polja koja korisnik smije
mijenjati (displayName, email) uz validaciju. Nepoznata polja (npr. ``role``) se ignoriraju, a
uloga se mijenja isključivo kroz administratorski proces.
"""

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from vulnshop.common.auth import CurrentUserDep, DbDep
from vulnshop.common.db import Database
from vulnshop.common.http import error

router = APIRouter(tags=["Lab02 – Mass assignment"])


class ProfileUpdate(BaseModel):
    """POPRAVAK: DTO samo s poljima koja korisnik smije mijenjati (bez role) + validacija."""

    model_config = ConfigDict(extra="ignore")  # nepoznata polja (npr. "role") se odbacuju

    display_name: str = Field(alias="displayName", min_length=1, max_length=100)
    email: str = Field(max_length=200, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@router.get("/api/lab02/profile")
def get_profile(user: CurrentUserDep, db: DbDep):
    return to_dto(load_profile(db, user.id))


@router.put("/api/lab02/profile")
def update_profile(update: ProfileUpdate, user: CurrentUserDep, db: DbDep):
    # POPRAVAK: zapisuju se samo dopuštena polja; uloga se ovdje ne može promijeniti.
    db.execute(
        "UPDATE lab02_profiles SET display_name = ?, email = ? WHERE user_id = ?",
        (update.display_name, update.email, user.id),
    )
    return to_dto(load_profile(db, user.id))


@router.get("/api/lab02/admin/users")
def admin_users(user: CurrentUserDep, db: DbDep):
    # Ovlast se provjerava prema ulozi iz tablice profila (koju je napadač mogao promijeniti).
    profile = load_profile(db, user.id)
    if profile["role"] != "ADMIN":
        return error(403, "Samo administrator smije vidjeti popis korisnika.")
    rows = db.query("SELECT user_id, display_name, email, role FROM lab02_profiles ORDER BY user_id")
    return [to_dto(row) for row in rows]


def load_profile(db: Database, user_id: int) -> dict:
    return db.query_one("SELECT user_id, display_name, email, role FROM lab02_profiles WHERE user_id = ?", (user_id,))


def to_dto(row: dict) -> dict:
    return {
        "userId": row["user_id"],
        "displayName": row["display_name"],
        "email": row["email"],
        "role": row["role"],
    }
