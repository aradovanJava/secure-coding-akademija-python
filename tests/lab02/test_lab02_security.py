"""Lab02 – mass assignment: sigurnosni testovi (koriste korisnika marko)."""

import pytest

pytestmark = [pytest.mark.security, pytest.mark.lab02]

ESCALATION = {"displayName": "Marko", "email": "m@x.hr", "role": "ADMIN"}


def test_marko_cannot_make_himself_admin(client, auth):
    """Nakon PUT /profile s "role": "ADMIN" profil i dalje mora imati ulogu USER."""
    client.put("/api/lab02/profile", headers=auth("marko"), json=ESCALATION)

    profile = client.get("/api/lab02/profile", headers=auth("marko")).json()
    assert profile["role"] == "USER"


def test_marko_has_no_access_to_admin_users(client, auth):
    """Ni nakon pokušaja eskalacije marko ne smije pristupiti admin/users (403)."""
    client.put("/api/lab02/profile", headers=auth("marko"), json=ESCALATION)

    response = client.get("/api/lab02/admin/users", headers=auth("marko"))
    assert response.status_code == 403
