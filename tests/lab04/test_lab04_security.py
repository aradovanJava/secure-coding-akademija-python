"""Lab04 – Security Misconfiguration: sigurnosni testovi."""

import pytest

pytestmark = [pytest.mark.security, pytest.mark.lab04]


def test_debug_config_endpoint_is_not_exposed(client):
    """/api/lab04/debug/config ne smije biti dostupan (404/401/403) niti otkrivati tajne."""
    response = client.get("/api/lab04/debug/config")

    assert response.status_code in (401, 403, 404)
    assert "sk_live_akademija_123" not in response.text


def test_crash_returns_500_without_traceback(client):
    """/api/lab04/crash vraća 500 bez tracebacka, naziva modula i klase iznimke."""
    response = client.get("/api/lab04/crash")

    assert response.status_code == 500
    for leak in ("Traceback", 'File "', "vulnshop", "RuntimeError", "sqlite3"):
        assert leak not in response.text, f"Odgovor otkriva: {leak}"


def test_cors_does_not_allow_evil_origin(client):
    """CORS preflight sa zlonamjernog origina ne smije biti dopušten."""
    response = client.options(
        "/api/lab04/ping",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )

    assert response.headers.get("access-control-allow-origin") not in ("https://evil.example", "*")


def test_ping_has_security_headers(client):
    """/api/lab04/ping mora imati sigurnosna zaglavlja (nosniff, X-Frame-Options DENY)."""
    response = client.get("/api/lab04/ping")

    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("x-frame-options") == "DENY"
