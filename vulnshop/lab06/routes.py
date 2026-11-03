"""Lab06 – A04 Cryptographic Failures (CWE-916, CWE-327, CWE-321, CWE-329).

Dio A (lozinke): registracija i prijava spremaju MD5 (heks, bez soli). Procurjeli "dump"
(``/api/lab06/customers/export``) omogućuje offline razbijanje: MD5 je brz, nema soli, a
iste lozinke daju isti hash.

Dio B (podaci): brojevi kartica šifriraju se AES-om u načinu ECB s HARDKODIRANIM ključem.
ECB otkriva obrasce (isti ulaz -> isti šifrat), a ključ iz izvornog koda zna svatko tko vidi kod.
"""

import base64
import hashlib

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fastapi import APIRouter
from pydantic import BaseModel, Field

from vulnshop.common.auth import DbDep
from vulnshop.common.http import error

router = APIRouter(tags=["Lab06 – Kriptografski propusti"])

# RANJIVO: hardkodirani 16-bajtni ključ izravno u izvornom kodu.
HARDCODED_KEY = b"AkademijaKljuc16"


# ------------------------------- Dio A: lozinke -------------------------------


def hash_password(password: str) -> str:
    # RANJIVO: MD5 bez soli (brz i deterministički).
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def verify_password(password_hash: str, password: str) -> bool:
    # RANJIVO: usporedba MD5 heksa.
    return password_hash == hash_password(password)


class Credentials(BaseModel):
    username: str | None = None
    password: str | None = None


@router.post("/api/lab06/register")
def register(body: Credentials, db: DbDep):
    if not body.username or not body.password:
        return error(400, "Nedostaje korisničko ime ili lozinka.")
    if db.query_one("SELECT id FROM lab06_customers WHERE username = ?", (body.username,)):
        return error(409, "Korisnik već postoji.")
    db.execute(
        "INSERT INTO lab06_customers (username, password_hash) VALUES (?, ?)",
        (body.username, hash_password(body.password)),
    )
    return {"username": body.username, "status": "registriran"}


@router.post("/api/lab06/login")
def login(body: Credentials, db: DbDep):
    if not body.username or body.password is None:
        return error(401, "Neispravni podaci.")
    row = db.query_one("SELECT password_hash FROM lab06_customers WHERE username = ?", (body.username,))
    if row is None or not verify_password(row["password_hash"], body.password):
        return error(401, "Neispravni podaci.")
    return {"username": body.username, "status": "prijavljen"}


@router.get("/api/lab06/customers/export")
def export_customers(db: DbDep):
    # NAMJERNO bez autentikacije: simulira procurjeli "dump" baze lozinki.
    return db.query("SELECT username, password_hash FROM lab06_customers ORDER BY username")


# ------------------------------- Dio B: kartice -------------------------------


class CardRequest(BaseModel):
    card_number: str | None = Field(default=None, alias="cardNumber")


def encrypt_card(card_number: str) -> str:
    # RANJIVO: AES u načinu ECB s hardkodiranim ključem (deterministički, bez IV-a/noncea).
    padder = padding.PKCS7(128).padder()
    padded = padder.update(card_number.encode("utf-8")) + padder.finalize()
    encryptor = Cipher(algorithms.AES(HARDCODED_KEY), modes.ECB()).encryptor()
    return base64.b64encode(encryptor.update(padded) + encryptor.finalize()).decode("ascii")


@router.post("/api/lab06/cards")
def store_card(body: CardRequest, db: DbDep):
    if not body.card_number or len(body.card_number) < 4:
        return error(400, "Neispravan broj kartice.")
    ciphertext = encrypt_card(body.card_number)
    card_id = db.insert(
        "INSERT INTO lab06_cards (owner, ciphertext, last4) VALUES (?, ?, ?)",
        ("demo", ciphertext, body.card_number[-4:]),
    )
    return {"id": card_id, "ciphertext": ciphertext}


@router.get("/api/lab06/cards")
def list_cards(db: DbDep):
    return db.query("SELECT id, ciphertext FROM lab06_cards ORDER BY id")


@router.get("/api/lab06/cards/{card_id}/masked")
def masked_card(card_id: int, db: DbDep):
    row = db.query_one("SELECT last4 FROM lab06_cards WHERE id = ?", (card_id,))
    if row is None:
        return error(404, "Kartica nije pronađena.")
    return {"masked": "**** **** **** " + row["last4"]}
