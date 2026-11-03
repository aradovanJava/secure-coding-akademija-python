"""Lab03 – SSRF: funkcionalni testovi."""

import pytest

pytestmark = [pytest.mark.functional, pytest.mark.lab03]


def test_unsupported_ftp_scheme_is_not_200(client, auth):
    """Nepodržana shema ftp:// ne smije vratiti 200 (ranjiva verzija vraća 502, ispravljena 400)."""
    response = client.get("/api/lab03/preview", params={"url": "ftp://127.0.0.1:1/datoteka.txt"}, headers=auth("ana"))

    assert response.status_code != 200


def test_without_token_returns_401(client):
    """Bez tokena pregled poveznice vraća 401."""
    response = client.get("/api/lab03/preview", params={"url": "https://example.com"})

    assert response.status_code == 401
