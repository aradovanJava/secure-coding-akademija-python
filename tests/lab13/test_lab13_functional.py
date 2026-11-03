"""Lab13 – nesigurna deserijalizacija: funkcionalni testovi."""

import pytest

from tests.lab13.payloads import legit_cart_payload

pytestmark = [pytest.mark.functional, pytest.mark.lab13]


def test_legitimate_cart_is_imported(client):
    """Legitimna košarica s 2 stavke vraća 200 i itemCount = 2."""
    response = client.post(
        "/api/lab13/cart/import", content=legit_cart_payload(), headers={"Content-Type": "text/plain"}
    )

    assert response.status_code == 200
    assert response.json()["itemCount"] == 2
