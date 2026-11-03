"""Lab11 – Authentication Failures: funkcionalni testovi."""

import pytest

pytestmark = [pytest.mark.functional, pytest.mark.lab11]


def test_valid_login(client):
    """Ispravna prijava korisnika tomislav vraća 200."""
    response = client.post("/api/lab11/login", json={"username": "tomislav", "password": "T0m!slav#2026"})

    assert response.status_code == 200
