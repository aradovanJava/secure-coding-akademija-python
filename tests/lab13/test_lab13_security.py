"""Lab13 – nesigurna deserijalizacija: sigurnosni testovi."""

import pytest

from tests.lab13.payloads import attack_payload

pytestmark = [pytest.mark.security, pytest.mark.lab13]


def test_attack_payload_is_rejected_and_has_no_effect(client, tmp_path):
    """Napadački sadržaj (DiagnosticsTask) mora vratiti 400 i NE smije stvoriti marker datoteku."""
    marker = tmp_path / "lab13-pwned.txt"

    response = client.post(
        "/api/lab13/cart/import", content=attack_payload(str(marker)), headers={"Content-Type": "text/plain"}
    )

    assert response.status_code == 400
    assert not marker.exists(), "Kod se izvršio tijekom deserijalizacije!"
