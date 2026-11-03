"""Lab02 – A01 Broken Access Control: mass assignment / eskalacija privilegija (CWE-915, CWE-269).

RANJIVO: ``PUT /api/lab02/profile`` prima model koji sadrži i polje ``role`` te ga zapisuje u
bazu. Korisnik tako sam sebi može postaviti ulogu ADMIN (mass assignment) i dobiti pristup
administratorskom endpointu ``GET /api/lab02/admin/users``.
"""

from fastapi import APIRouter
from pydantic import BaseModel, Field

from vulnshop.common.auth import CurrentUserDep, DbDep
from vulnshop.common.db import Database
from vulnshop.common.http import error

router = APIRouter(tags=["Lab02 – Mass assignment"])


class ProfileUpdate(BaseModel):
    """RANJIVO: model prihvaća i polje role iz tijela zahtjeva."""

    display_name: str | None = Field(default=None, alias="displayName")
    email: str | None = None
    role: str | None = None


@router.get("/api/lab02/profile")
def get_profile(user: CurrentUserDep, db: DbDep):
    return to_dto(load_profile(db, user.id))


@router.put("/api/lab02/profile")
def update_profile(update: ProfileUpdate, user: CurrentUserDep, db: DbDep):
    # RANJIVO: role dolazi izravno iz JSON-a i zapisuje se bez provjere (mass assignment).
    # Legitimni klijent ne šalje role (COALESCE zadržava postojeću vrijednost), ali napadač
    # može poslati "role": "ADMIN" i tako eskalirati privilegije.
    db.execute(
        "UPDATE lab02_profiles SET display_name = COALESCE(?, display_name), email = COALESCE(?, email), "
        "role = COALESCE(?, role) WHERE user_id = ?",
        (update.display_name, update.email, update.role, user.id),
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
