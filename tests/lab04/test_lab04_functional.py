"""Lab04 – Security Misconfiguration: funkcionalni testovi."""

import pytest

pytestmark = [pytest.mark.functional, pytest.mark.lab04]


def test_health_is_available(client):
    """/health je dostupan (200)."""
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "UP"


def test_ping_works(client):
    """/api/lab04/ping vraća 200."""
    assert client.get("/api/lab04/ping").status_code == 200
