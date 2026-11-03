"""Lab09 – OS command injection: sigurnosni testovi."""

import pytest

pytestmark = [pytest.mark.security, pytest.mark.lab09]


def test_ampersand_chaining_is_blocked(client):
    """Payload '127.0.0.1 & echo PWNED_LAB09' mora vratiti 400 bez izvršenja naredbe."""
    response = client.get("/api/lab09/ping", params={"host": "127.0.0.1 & echo PWNED_LAB09"})

    assert response.status_code == 400
    assert "PWNED_LAB09" not in response.text


def test_semicolon_chaining_is_blocked(client):
    """Payload '127.0.0.1;id' mora vratiti 400."""
    response = client.get("/api/lab09/ping", params={"host": "127.0.0.1;id"})

    assert response.status_code == 400
