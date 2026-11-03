"""Lab08 – A05 Injection: Cross-Site Scripting (CWE-79) – ISPRAVLJENO.

POPRAVAK:

* kontekstualno kodiranje izlaza: svaki korisnički podatak prolazi kroz ``html.escape`` prije
  upisa u HTML (``<`` -> ``&lt;``, ``"`` -> ``&quot;`` ...), pa preglednik ne izvršava skriptu,
* validacija ulaza (duljina recenzije i autora),
* zaglavlje Content-Security-Policy kao drugi sloj obrane (blokira inline skripte).

Napomena: predlošci (Jinja2 s ``autoescape=True``, Django) kodiraju automatski; opasni su
``|safe``, ``Markup(...)`` i isključeni autoescape.
"""

import html

from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from vulnshop.common.auth import DbDep

router = APIRouter(tags=["Lab08 – XSS"])

PAGE_START = '<!DOCTYPE html><html lang="hr"><head><meta charset="UTF-8"><title>{title}</title></head><body>'
PAGE_END = "</body></html>"
# POPRAVAK: CSP – skripte samo s vlastitog izvora, bez inline skripti i pluginova.
CSP = "default-src 'self'; script-src 'self'; object-src 'none'"


def html_page(content: str) -> HTMLResponse:
    return HTMLResponse(content, headers={"Content-Security-Policy": CSP})


@router.get("/lab08/search", response_class=HTMLResponse)
def search(q: str = ""):
    # POPRAVAK: kodiranje izlaza.
    body = "<h1>Rezultati pretrage za: " + html.escape(q) + "</h1>"
    return html_page(PAGE_START.format(title="Pretraga") + body + PAGE_END)


class ReviewRequest(BaseModel):
    product_id: int = Field(alias="productId")
    # POPRAVAK: validacija ulaza (duljina).
    author: str = Field(min_length=1, max_length=100)
    text: str = Field(min_length=1, max_length=2000)


@router.post("/api/lab08/reviews")
def add_review(body: ReviewRequest, db: DbDep):
    db.execute(
        "INSERT INTO lab08_reviews (product_id, author, text) VALUES (?, ?, ?)",
        (body.product_id, body.author, body.text),
    )
    return {"status": "spremljeno"}


@router.get("/lab08/products/{product_id}/reviews", response_class=HTMLResponse)
def reviews(product_id: int, db: DbDep):
    rows = db.query("SELECT author, text FROM lab08_reviews WHERE product_id = ? ORDER BY id", (product_id,))
    page = PAGE_START.format(title="Recenzije") + f"<h1>Recenzije za proizvod {product_id}</h1>"
    for row in rows:
        # POPRAVAK: author i text kodiraju se pri ispisu (pohranjeni podaci su i dalje nepouzdani).
        page += f'<div class="review"><strong>{html.escape(row["author"])}</strong>: {html.escape(row["text"])}</div>'
    return html_page(page + PAGE_END)
