"""Lab09 – OS command injection: funkcionalni testovi."""

import pytest

pytestmark = [pytest.mark.functional, pytest.mark.lab09]


def test_valid_host_returns_200(client):
    """Ispravan host 127.0.0.1 vraća 200 (neovisno o tome je li ping uspio)."""
    response = client.get("/api/lab09/ping", params={"host": "127.0.0.1"})

    assert response.status_code == 200
