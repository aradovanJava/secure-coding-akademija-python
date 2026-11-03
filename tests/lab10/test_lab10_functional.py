"""Lab10 – Insecure Design (poslovna logika): funkcionalni testovi."""

from decimal import Decimal

import pytest

pytestmark = [pytest.mark.functional, pytest.mark.lab10]


def test_valid_checkout_reduces_balance(client, auth):
    """Ispravan checkout (1x Kabel 9.99) umanjuje stanje točno za 9.99."""
    headers = auth("ana")
    before = Decimal(str(client.get("/api/lab10/wallet", headers=headers).json()["balance"]))

    response = client.post(
        "/api/lab10/checkout", headers=headers, json={"items": [{"productId": 3, "quantity": 1, "unitPrice": 9.99}]}
    )

    after = Decimal(str(client.get("/api/lab10/wallet", headers=headers).json()["balance"]))
    assert response.status_code == 200
    assert before - after == Decimal("9.99")
