"""Lab07 – SQL injection: sigurnosni testovi."""

import pytest

pytestmark = [pytest.mark.security, pytest.mark.lab07]


def test_or_injection_does_not_reveal_hidden_product(client):
    """Payload ' OR '1'='1' -- ne smije otkriti skriveni proizvod (Interni prototip X)."""
    response = client.get("/api/lab07/products/search", params={"q": "' OR '1'='1' --"})

    assert response.status_code in (200, 400)
    assert "Interni prototip X" not in response.text


def test_union_does_not_reveal_accounts(client):
    """UNION payload ne smije vratiti korisnička imena i lozinke iz tablice lab07_accounts."""
    payload = "%' UNION SELECT id, username, password, 0 FROM lab07_accounts --"
    response = client.get("/api/lab07/products/search", params={"q": payload})

    assert response.status_code in (200, 400)
    assert "SuperTajna2026" not in response.text
    assert "webshop" not in response.text


def test_login_bypass_is_rejected(client):
    """Prijava s korisničkim imenom admin'-- i bilo kojom lozinkom mora biti odbijena (401)."""
    response = client.post("/api/lab07/login", json={"username": "admin'--", "password": "bilo-sto"})

    assert response.status_code == 401
