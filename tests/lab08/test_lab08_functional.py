"""Lab08 – Cross-Site Scripting: funkcionalni testovi."""

import pytest

pytestmark = [pytest.mark.functional, pytest.mark.lab08]


def test_plain_search_shows_term(client):
    """Obična pretraga prikazuje uneseni pojam."""
    response = client.get("/lab08/search", params={"q": "laptop"})

    assert response.status_code == 200
    assert "Rezultati pretrage za: laptop" in response.text


def test_plain_review_is_saved_and_shown(client):
    """Obična recenzija se sprema i prikazuje."""
    client.post("/api/lab08/reviews", json={"productId": 802, "author": "Iva", "text": "Brza dostava"})

    response = client.get("/lab08/products/802/reviews")
    assert response.status_code == 200
    assert "Brza dostava" in response.text
