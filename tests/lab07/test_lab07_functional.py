"""Lab07 – SQL injection: funkcionalni testovi."""

import pytest

pytestmark = [pytest.mark.functional, pytest.mark.lab07]


def test_search_laptop_returns_one_result(client):
    """Pretraga q=Laptop vraća točno jedan rezultat."""
    response = client.get("/api/lab07/products/search", params={"q": "Laptop"})

    assert response.status_code == 200
    assert [product["name"] for product in response.json()] == ["Laptop"]


def test_valid_login(client):
    """Ispravna prijava računa admin / SuperTajna2026 vraća 200."""
    response = client.post("/api/lab07/login", json={"username": "admin", "password": "SuperTajna2026"})

    assert response.status_code == 200
