"""Lab08 – Cross-Site Scripting: sigurnosni testovi."""

import pytest

pytestmark = [pytest.mark.security, pytest.mark.lab08]


def test_reflected_xss_is_encoded(client):
    """Reflektirani XSS: odgovor ne smije sadržavati nekodirani <script>, nego &lt;script&gt;."""
    response = client.get("/lab08/search", params={"q": "<script>alert(1)</script>"})

    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;" in response.text


def test_stored_xss_is_encoded(client):
    """Pohranjeni XSS: recenzija s <img onerror> mora u HTML-u biti kodirana."""
    client.post(
        "/api/lab08/reviews",
        json={"productId": 801, "author": "Napadač", "text": "<img src=x onerror=alert('XSS')>"},
    )

    response = client.get("/lab08/products/801/reviews")
    assert "<img src=x onerror=" not in response.text
    assert "&lt;img" in response.text


def test_csp_header_with_script_src(client):
    """Odgovor mora imati zaglavlje Content-Security-Policy sa script-src."""
    response = client.get("/lab08/search", params={"q": "test"})

    assert "script-src" in response.headers.get("content-security-policy", "")
