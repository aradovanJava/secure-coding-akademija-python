"""Lab01 – IDOR: sigurnosni testovi (na grani main PADAJU, nakon popravka PROLAZE)."""

import pytest

pytestmark = [pytest.mark.security, pytest.mark.lab01]


def test_ana_cannot_read_other_users_order(client, auth):
    """Ana ne smije dohvatiti Markovu narudžbu 1003 – mora dobiti 404 (ne otkrivamo ni postojanje)."""
    response = client.get("/api/lab01/orders/1003", headers=auth("ana"))

    assert response.status_code == 404
    assert "marko" not in response.text
