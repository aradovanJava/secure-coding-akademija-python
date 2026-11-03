"""Lab14 – Security Logging & Alerting Failures: sigurnosni testovi.

Zapisi u log hvataju se ugrađenim pytest fixtureom ``caplog``.
"""

import logging

import pytest

pytestmark = [pytest.mark.security, pytest.mark.lab14]

LOGGER = "vulnshop.lab14"
FORGED_LINE = "2026-11-02 10:00:00 INFO Login successful user=admin"


def _messages(caplog) -> list[str]:
    return [record.getMessage() for record in caplog.records if record.name.startswith(LOGGER)]


def test_password_is_not_logged(client, caplog):
    """Lozinka se NE smije pojaviti u logu."""
    caplog.set_level(logging.DEBUG, logger=LOGGER)

    client.post("/api/lab14/login", json={"username": "ana", "password": "Ana123!"})

    assert not any("Ana123!" in message for message in _messages(caplog))


def test_no_log_injection(client, caplog):
    """Korisničko ime s \\n ne smije proizvesti krivotvoreni redak u logu (log injection)."""
    caplog.set_level(logging.DEBUG, logger=LOGGER)

    client.post("/api/lab14/login", json={"username": "ana\n" + FORGED_LINE, "password": "x"})

    lines = [line for message in _messages(caplog) for line in message.splitlines()]
    assert not any(line.startswith(FORGED_LINE) for line in lines)


def test_failed_login_creates_security_event(client, caplog):
    """Neuspjela prijava mora proizvesti zapis SECURITY_EVENT ... LOGIN_FAILED."""
    caplog.set_level(logging.DEBUG, logger=LOGGER)

    client.post("/api/lab14/login", json={"username": "ana", "password": "kriva"})

    assert any("SECURITY_EVENT" in m and "LOGIN_FAILED" in m for m in _messages(caplog))


def test_five_failures_raise_alert(client, caplog):
    """Nakon 5 neuspjelih prijava za istog korisnika mora postojati zapis SECURITY_ALERT."""
    caplog.set_level(logging.DEBUG, logger=LOGGER)

    for _ in range(5):
        client.post("/api/lab14/login", json={"username": "marko", "password": "pogresna"})

    assert any("SECURITY_ALERT" in message for message in _messages(caplog))
