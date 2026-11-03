"""Lab06 – A04 Cryptographic Failures (CWE-916, CWE-327, CWE-321, CWE-329) – ISPRAVLJENO.

Dio A (lozinke) – POPRAVAK: lozinke se hashiraju algoritmom Argon2id (argon2-cffi). Funkcija je
namjerno spora i memorijski zahtjevna, a svaki hash ima vlastitu nasumičnu sol – iste lozinke
daju različite hasheve, a offline razbijanje postaje višestruko skuplje.

Dio B (podaci) – POPRAVAK: brojevi kartica šifriraju se AES-GCM-om (autentificirano šifriranje)
s nasumičnim 12-bajtnim nonceom za svaki zapis. Ključ (256 bita) NIJE u kodu – čita se iz
konfiguracije / okoline (LAB06_KEY); u produkciji iz KMS-a ili Key Vaulta.
"""

import base64
import os
from typing import Annotated

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from vulnshop.common.auth import DbDep
from vulnshop.common.http import error

router = APIRouter(tags=["Lab06 – Kriptografski propusti"])

# ------------------------------- Dio A: lozinke -------------------------------

# POPRAVAK: Argon2id sa zadanim (OWASP) parametrima; sol se generira za svaki hash.
_password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


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

NONCE_SIZE = 12  # 96 bita – preporučena veličina noncea za GCM


def get_card_cipher(request: Request) -> AESGCM:
    # POPRAVAK: ključ iz konfiguracije (LAB06_KEY, Base64, 32 B), a ne iz izvornog koda.
    key = base64.b64decode(request.app.state.settings.lab06_encryption_key)
    return AESGCM(key)


CipherDep = Annotated[AESGCM, Depends(get_card_cipher)]


class CardRequest(BaseModel):
    card_number: str | None = Field(default=None, alias="cardNumber")


def encrypt_card(cipher: AESGCM, card_number: str) -> str:
    # POPRAVAK: AES-GCM s nasumičnim nonceom; pohranjuje se nonce || šifrat || oznaka (tag).
    nonce = os.urandom(NONCE_SIZE)
    ciphertext_and_tag = cipher.encrypt(nonce, card_number.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext_and_tag).decode("ascii")


def decrypt_card(cipher: AESGCM, stored: str) -> str:
    data = base64.b64decode(stored)
    return cipher.decrypt(data[:NONCE_SIZE], data[NONCE_SIZE:], None).decode("utf-8")


@router.post("/api/lab06/cards")
def store_card(body: CardRequest, db: DbDep, cipher: CipherDep):
    if not body.card_number or len(body.card_number) < 4:
        return error(400, "Neispravan broj kartice.")
    ciphertext = encrypt_card(cipher, body.card_number)
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
