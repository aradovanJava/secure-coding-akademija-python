"""Lab10 – Insecure Design (poslovna logika): sigurnosni testovi.

Testovi mjere RAZLIKU stanja novčanika (prije/poslije), a ne apsolutne vrijednosti.
"""

from decimal import Decimal

import pytest

pytestmark = [pytest.mark.security, pytest.mark.lab10]


def _balance(client, headers) -> Decimal:
    return Decimal(str(client.get("/api/lab10/wallet", headers=headers).json()["balance"]))


def test_negative_quantity_is_rejected(client, auth):
    """Negativna količina (-5) mora vratiti 400 i NE smije promijeniti stanje novčanika."""
    headers = auth("marko")
    before = _balance(client, headers)

    response = client.post(
        "/api/lab10/checkout", headers=headers, json={"items": [{"productId": 1, "quantity": -5, "unitPrice": 899.00}]}
    )

    assert response.status_code == 400
    assert _balance(client, headers) == before


def test_client_price_is_ignored(client, auth):
    """Lažnom cijenom 0.01 za laptop ne smije se naplatiti 0.01 (cijena dolazi iz baze: 899.00)."""
    headers = auth("admin")
    before = _balance(client, headers)

    response = client.post(
        "/api/lab10/checkout", headers=headers, json={"items": [{"productId": 1, "quantity": 1, "unitPrice": 0.01}]}
    )

    charged = before - _balance(client, headers)
    if response.status_code == 200:
        assert charged == Decimal("899.00")
    else:
        assert response.status_code == 400
        assert charged == 0


def test_repeated_coupon_is_not_stacked(client, auth):
    """Isti kupon tri puta mora biti odbijen (400) ili popust primijenjen samo jednom."""
    headers = auth("marko")
    before = _balance(client, headers)

    response = client.post(
        "/api/lab10/checkout",
        headers=headers,
        json={
            "items": [{"productId": 2, "quantity": 1, "unitPrice": 99.00}],
            "couponCodes": ["AKADEMIJA10", "AKADEMIJA10", "AKADEMIJA10"],
        },
    )

    charged = before - _balance(client, headers)
    if response.status_code == 200:
        assert charged == Decimal("89.10")
    else:
        assert response.status_code == 400
        assert charged == 0
