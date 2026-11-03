"""Lab06 – Cryptographic Failures: funkcionalni testovi."""

import uuid

import pytest

pytestmark = [pytest.mark.functional, pytest.mark.lab06]


def test_register_and_login(client):
    """Registracija pa prijava točnom lozinkom -> 200, krivom -> 401."""
    username = f"f-{uuid.uuid4().hex[:8]}"
    client.post("/api/lab06/register", json={"username": username, "password": "Jesen2026!"})

    assert client.post("/api/lab06/login", json={"username": username, "password": "Jesen2026!"}).status_code == 200
    assert client.post("/api/lab06/login", json={"username": username, "password": "kriva"}).status_code == 401


def test_seed_customer_can_log_in(client):
    """Seed kupac ivan (lozinka 123456) može se prijaviti – i nakon promjene načina hashiranja."""
    assert client.post("/api/lab06/login", json={"username": "ivan", "password": "123456"}).status_code == 200


def test_masked_card(client):
    """Maskirani prikaz kartice prikazuje samo zadnje 4 znamenke."""
    card_id = client.post("/api/lab06/cards", json={"cardNumber": "5555555555554444"}).json()["id"]

    response = client.get(f"/api/lab06/cards/{card_id}/masked")
    assert response.status_code == 200
    assert response.json()["masked"] == "**** **** **** 4444"
