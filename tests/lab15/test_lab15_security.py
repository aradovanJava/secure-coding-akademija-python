"""Lab15 – Mishandling of Exceptional Conditions: sigurnosni testovi.

Testovi mjere RAZLIKU salda (prije/poslije), a ne apsolutne vrijednosti.
"""

from decimal import Decimal

import pytest

pytestmark = [pytest.mark.security, pytest.mark.lab15]


def _balance(client, headers, account: str) -> Decimal:
    rows = client.get("/api/lab15/accounts", headers=headers).json()
    return next(Decimal(str(row["balance"])) for row in rows if row["accountNo"] == account)


def test_unknown_currency_fails_closed(client, auth):
    """Transfer 50000 s nepoznatom valutom XYZ mora biti odbijen (4xx), a saldo nepromijenjen."""
    headers = auth("ana")
    before = _balance(client, headers, "HR-ANA-001")

    response = client.post(
        "/api/lab15/transfer",
        headers=headers,
        json={"fromAccount": "HR-ANA-001", "toAccount": "HR-MARKO-001", "amount": "50000", "currency": "XYZ"},
    )

    assert 400 <= response.status_code < 500
    assert _balance(client, headers, "HR-ANA-001") == before


def test_transfer_to_missing_account_keeps_balance(client, auth):
    """Transfer na nepostojeći račun mora biti odbijen (4xx) i ostaviti saldo nepromijenjen (transakcija)."""
    headers = auth("ana")
    before = _balance(client, headers, "HR-ANA-001")

    response = client.post(
        "/api/lab15/transfer",
        headers=headers,
        json={"fromAccount": "HR-ANA-001", "toAccount": "HR-NEPOSTOJECI-999", "amount": "100.00", "currency": "EUR"},
    )

    assert 400 <= response.status_code < 500
    assert _balance(client, headers, "HR-ANA-001") == before


def test_error_body_does_not_leak_details(client, auth):
    """Tijelo greške ne smije sadržavati naziv klase iznimke, modula, tablice ni SQL."""
    response = client.post(
        "/api/lab15/transfer",
        headers=auth("ana"),
        json={"fromAccount": "HR-ANA-001", "toAccount": "HR-NEPOSTOJECI-999", "amount": "abc", "currency": "EUR"},
    )

    assert response.status_code >= 400
    for leak in ("Error", "Exception", "decimal", "builtins", "lab15_accounts", "UPDATE", "SELECT"):
        assert leak not in response.text, f"Odgovor otkriva: {leak}"
