"""Lab05 – Software Supply Chain Failures: sigurnosni testovi."""

from importlib.metadata import version

import pytest

pytestmark = [pytest.mark.security, pytest.mark.lab05]


def _version_tuple(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.split(".")[:3])


def test_user_input_is_not_evaluated_as_template(client):
    """Ime {{ 7*7 }} mora se vratiti doslovno, a ne izvršiti kao izraz predloška (49)."""
    response = client.post("/api/lab05/greeting", json={"name": "{{ 7*7 }}"})

    assert response.status_code == 200
    assert response.json()["greeting"] == "Pozdrav, {{ 7*7 }}!"


def test_jinja2_version_is_not_vulnerable():
    """Instalirana verzija jinja2 mora biti >= 3.1.6 (CVE-2024-56326, CVE-2025-27516)."""
    installed = version("jinja2")

    assert _version_tuple(installed) >= (3, 1, 6), f"Ranjiva verzija jinja2 {installed}"
