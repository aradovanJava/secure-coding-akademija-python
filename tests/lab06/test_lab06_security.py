"""Lab06 – Cryptographic Failures: sigurnosni testovi (dio A lozinke, dio B kartice)."""

import base64
import hashlib
import re
import uuid

import pytest
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

pytestmark = [pytest.mark.security, pytest.mark.lab06]

CARD = "4111111111111111"


def _exported_hash(client, username: str) -> str:
    rows = client.get("/api/lab06/customers/export").json()
    return next(row["password_hash"] for row in rows if row["username"] == username)


def _register_two_users_with_same_password(client) -> tuple[str, str, str]:
    password = "Ljeto2026!"
    first, second = f"t1-{uuid.uuid4().hex[:8]}", f"t2-{uuid.uuid4().hex[:8]}"
    for username in (first, second):
        assert client.post("/api/lab06/register", json={"username": username, "password": password}).status_code == 200
    return first, second, password


def test_same_password_gives_different_hashes(client):
    """Dva korisnika s istom lozinkom moraju imati različite hasheve (sol)."""
    first, second, _ = _register_two_users_with_same_password(client)

    assert _exported_hash(client, first) != _exported_hash(client, second)


def test_hash_is_not_md5(client):
    """Pohranjeni hash ne smije biti MD5 lozinke niti 32 heksadekadska znaka."""
    first, _, password = _register_two_users_with_same_password(client)
    stored = _exported_hash(client, first)

    assert stored != hashlib.md5(password.encode()).hexdigest()  # noqa: S324
    assert not re.fullmatch(r"[0-9a-f]{32}", stored)


def test_same_card_gives_different_ciphertexts(client):
    """Dvaput isti broj kartice mora dati različite šifrate (nasumični nonce, ne ECB)."""
    first = client.post("/api/lab06/cards", json={"cardNumber": CARD}).json()["ciphertext"]
    second = client.post("/api/lab06/cards", json={"cardNumber": CARD}).json()["ciphertext"]

    assert first != second


def test_ciphertext_contains_nonce_and_tag(client):
    """Šifrat mora biti dulji od 16 + 12 bajtova (nonce i autentikacijska oznaka uz podatke)."""
    ciphertext = client.post("/api/lab06/cards", json={"cardNumber": CARD}).json()["ciphertext"]

    assert len(base64.b64decode(ciphertext)) > 16 + 12


def test_hardcoded_key_no_longer_decrypts(client):
    """Ključ "AkademijaKljuc16" u ECB načinu više ne smije dešifrirati broj kartice."""
    ciphertext = base64.b64decode(client.post("/api/lab06/cards", json={"cardNumber": CARD}).json()["ciphertext"])
    try:
        decryptor = Cipher(algorithms.AES(b"AkademijaKljuc16"), modes.ECB()).decryptor()  # noqa: S305
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = (unpadder.update(padded) + unpadder.finalize()).decode("utf-8")
    except ValueError:  # neispravna duljina ili padding -> ključ ne odgovara (očekivano)
        plaintext = None

    assert plaintext != CARD
