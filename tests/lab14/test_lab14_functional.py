"""Lab14 – Security Logging & Alerting Failures: funkcionalni testovi."""

import pytest

pytestmark = [pytest.mark.functional, pytest.mark.lab14]


def test_valid_login(client):
    """Ispravna prijava vraća 200."""
    response = client.post("/api/lab14/login", json={"username": "ana", "password": "Ana123!"})

    assert response.status_code == 200
