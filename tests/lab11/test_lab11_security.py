"""Lab11 – Authentication Failures (brute force, enumeracija): sigurnosni testovi."""

import pytest

pytestmark = [pytest.mark.security, pytest.mark.lab11]


def test_no_user_enumeration(client):
    """Nepostojeći korisnik i kriva lozinka moraju dati isti status i isto tijelo odgovora."""
    unknown_user = client.post("/api/lab11/login", json={"username": "ne-postoji-123", "password": "x"})
    wrong_password = client.post("/api/lab11/login", json={"username": "tomislav", "password": "kriva-lozinka"})

    assert unknown_user.status_code == wrong_password.status_code
    assert unknown_user.json() == wrong_password.json()


def test_account_is_locked_after_five_failures(client):
    """Nakon 5 neuspjelih pokušaja za korisnika 'lockme' i ispravna lozinka mora vratiti 429."""
    for _ in range(5):
        client.post("/api/lab11/login", json={"username": "lockme", "password": "pogresna"})

    response = client.post("/api/lab11/login", json={"username": "lockme", "password": "Lock!Me2026"})

    assert response.status_code == 429
