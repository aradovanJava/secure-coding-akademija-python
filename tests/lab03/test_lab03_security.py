"""Lab03 – SSRF: sigurnosni testovi.

Koriste stvarni poslužitelj (fixture ``live_server``) jer se ranjivost vidi tek kad poslužitelj
pošalje zahtjev SAM SEBI na loopback adresu.
"""

import httpx
import pytest

pytestmark = [pytest.mark.security, pytest.mark.lab03]

SECRET = "Sup3rTajn0!"


def preview(live_server, target_url: str) -> httpx.Response:
    return httpx.get(
        f"{live_server.base_url}/api/lab03/preview",
        params={"url": target_url},
        headers=live_server.auth("ana"),
        timeout=20,
    )


def test_ssrf_to_loopback_ip_is_blocked(live_server):
    """SSRF na 127.0.0.1 (interni endpoint s tajnama) mora vratiti 400 i bez tajne."""
    response = preview(live_server, f"http://127.0.0.1:{live_server.port}/internal/admin/secrets")

    assert response.status_code == 400
    assert SECRET not in response.text


def test_ssrf_via_localhost_name_is_blocked(live_server):
    """SSRF preko imena localhost mora biti blokiran (400) i bez tajne."""
    response = preview(live_server, f"http://localhost:{live_server.port}/internal/admin/secrets")

    assert response.status_code == 400
    assert SECRET not in response.text


def test_ssrf_to_ipv6_loopback_is_blocked(live_server):
    """SSRF na [::1] (IPv6 loopback) mora biti blokiran (400)."""
    response = preview(live_server, f"http://[::1]:{live_server.port}/internal/admin/secrets")

    assert response.status_code == 400


def test_ssrf_to_cloud_metadata_is_blocked(live_server):
    """SSRF na cloud metadata adresu 169.254.169.254 mora biti blokiran (400)."""
    response = preview(live_server, "http://169.254.169.254/latest/meta-data/")

    assert response.status_code == 400


def test_file_scheme_is_blocked(live_server, tmp_path):
    """SSRF preko sheme file:// (čitanje lokalnih datoteka) mora biti blokiran (400)."""
    secret_file = tmp_path / "lab03-tajna.txt"
    secret_file.write_text("LAB03_LOKALNA_TAJNA", encoding="utf-8")

    response = preview(live_server, secret_file.as_uri())

    assert response.status_code == 400
    assert "LAB03_LOKALNA_TAJNA" not in response.text
