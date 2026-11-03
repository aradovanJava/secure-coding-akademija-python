"""Lab08 – A05 Injection: Cross-Site Scripting (CWE-79).

RANJIVO: HTML stranice grade se spajanjem stringova s korisničkim unosom, bez kodiranja
izlaza. Reflektirani XSS u pretrazi (``/lab08/search``) i pohranjeni XSS u recenzijama
(``/lab08/products/{id}/reviews``).
"""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from vulnshop.common.auth import DbDep

router = APIRouter(tags=["Lab08 – XSS"])

PAGE_START = '<!DOCTYPE html><html lang="hr"><head><meta charset="UTF-8"><title>{title}</title></head><body>'
PAGE_END = "</body></html>"


@router.get("/lab08/search", response_class=HTMLResponse)
def search(q: str = ""):
    # RANJIVO: reflektirani XSS – q se upisuje izravno u HTML.
    html = PAGE_START.format(title="Pretraga") + "<h1>Rezultati pretrage za: " + q + "</h1>" + PAGE_END
    return HTMLResponse(html)


class ReviewRequest(BaseModel):
    product_id: int = Field(alias="productId")
    author: str
    text: str


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
    html = PAGE_START.format(title="Recenzije") + f"<h1>Recenzije za proizvod {product_id}</h1>"
    for row in rows:
        # RANJIVO: pohranjeni XSS – author i text upisuju se izravno u HTML.
        html += '<div class="review"><strong>' + row["author"] + "</strong>: " + row["text"] + "</div>"
    return HTMLResponse(html + PAGE_END)
