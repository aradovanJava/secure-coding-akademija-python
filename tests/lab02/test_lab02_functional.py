"""Lab02 – mass assignment: funkcionalni testovi (koriste korisnike ana i admin)."""

import pytest

pytestmark = [pytest.mark.functional, pytest.mark.lab02]


def test_ana_can_change_display_name(client, auth):
    """Ana smije promijeniti svoje ime (displayName) kroz PUT /profile."""
    response = client.put(
        "/api/lab02/profile", headers=auth("ana"), json={"displayName": "Ana A.", "email": "ana@akademija.hr"}
    )

    assert response.status_code == 200
    assert response.json()["displayName"] == "Ana A."


def test_admin_can_list_users(client, auth):
    """Administrator smije vidjeti popis korisnika (admin/users -> 200)."""
    response = client.get("/api/lab02/admin/users", headers=auth("admin"))

    assert response.status_code == 200
    assert len(response.json()) == 3
