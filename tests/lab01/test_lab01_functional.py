"""Lab01 – IDOR: funkcionalni testovi (prolaze uvijek)."""

import pytest

pytestmark = [pytest.mark.functional, pytest.mark.lab01]


def test_ana_can_read_own_order(client, auth):
    """Ana smije dohvatiti vlastitu narudžbu 1001 (200)."""
    response = client.get("/api/lab01/orders/1001", headers=auth("ana"))

    assert response.status_code == 200
    assert response.json()["owner"] == "ana"


def test_admin_can_read_any_order(client, auth):
    """Administrator smije dohvatiti bilo koju narudžbu, npr. 1003 (200)."""
    response = client.get("/api/lab01/orders/1003", headers=auth("admin"))

    assert response.status_code == 200
    assert response.json()["owner"] == "marko"


def test_without_token_returns_401(client):
    """Bez tokena dohvat narudžbe vraća 401."""
    assert client.get("/api/lab01/orders/1001").status_code == 401
