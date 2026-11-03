"""Lab15 – Mishandling of Exceptional Conditions: funkcionalni testovi."""

from decimal import Decimal

import pytest

pytestmark = [pytest.mark.functional, pytest.mark.lab15]


def test_valid_transfer_reduces_balance(client, auth):
    """Ispravan transfer 100 EUR vraća 200 i smanjuje saldo točno za 100 (mjeri se razlika)."""
    headers = auth("ana")

    def balance() -> Decimal:
        rows = client.get("/api/lab15/accounts", headers=headers).json()
        return next(Decimal(str(row["balance"])) for row in rows if row["accountNo"] == "HR-ANA-001")

    before = balance()
    response = client.post(
        "/api/lab15/transfer",
        headers=headers,
        json={"fromAccount": "HR-ANA-001", "toAccount": "HR-MARKO-001", "amount": "100.00", "currency": "EUR"},
    )

    assert response.status_code == 200
    assert before - balance() == Decimal("100.00")
