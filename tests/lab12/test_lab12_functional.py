"""Lab12 – JWT propusti: funkcionalni testovi."""

import pytest

pytestmark = [pytest.mark.functional, pytest.mark.lab12]


def _jwt(client, username: str, password: str) -> dict[str, str]:
    response = client.post("/api/lab12/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['token']}"}


def test_login_then_me(client):
    """Prijava pa /me vraća 200 i ispravan subject."""
    response = client.get("/api/lab12/me", headers=_jwt(client, "ana", "Ana123!"))

    assert response.status_code == 200
    assert response.json()["sub"] == "ana"


def test_user_on_admin_gets_403(client):
    """Korisnik s ulogom USER na /admin dobiva 403."""
    assert client.get("/api/lab12/admin", headers=_jwt(client, "ana", "Ana123!")).status_code == 403


def test_admin_on_admin_gets_200(client):
    """Prijava administratora pa /admin vraća 200."""
    assert client.get("/api/lab12/admin", headers=_jwt(client, "admin", "Admin123!")).status_code == 200
