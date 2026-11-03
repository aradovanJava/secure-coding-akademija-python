"""Lab05 – Software Supply Chain Failures: funkcionalni testovi."""

import pytest

pytestmark = [pytest.mark.functional, pytest.mark.lab05]


def test_plain_greeting_works(client):
    """Običan pozdrav vraća očekivani tekst s imenom."""
    response = client.post("/api/lab05/greeting", json={"name": "Ana"})

    assert response.status_code == 200
    assert response.json()["greeting"] == "Pozdrav, Ana!"
