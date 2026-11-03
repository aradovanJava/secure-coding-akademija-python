# Lab08 – Cross-Site Scripting (XSS)

## 1. Cilj vježbe

Pokazati reflektirani i pohranjeni XSS kad se HTML gradi spajanjem stringova bez kodiranja izlaza, te ga
ispraviti kontekstualnim kodiranjem, validacijom ulaza i zaglavljem *Content-Security-Policy*.

- **OWASP Top 10:2025:** A05 – Injection
- **CWE:** CWE-79 (*Cross-site Scripting*)

## 2. Gdje je kod

- `vulnshop/lab08/routes.py`
  - funkcija `search(q)` → `GET /lab08/search?q=` (reflektirani; vraća `text/html`)
  - funkcija `add_review(body, db)` → `POST /api/lab08/reviews`
  - funkcija `reviews(product_id, db)` → `GET /lab08/products/{id}/reviews` (pohranjeni; vraća `text/html`)
- Podaci: `vulnshop/lab08/data.py` (tablica `lab08_reviews` s jednom početnom recenzijom).
- Testovi: `tests/lab08/test_lab08_security.py`, `tests/lab08/test_lab08_functional.py`.

## 3. Opis ranjivosti

HTML stranice nastaju spajanjem stringova s korisničkim unosom (`"...za: " + q`, autor i tekst recenzije), bez ikakvog kodiranja. Preglednik tada izvršava ubačeni `<script>` ili `onerror` handler. Nema ni CSP-a kao druge crte obrane.

## 4. Eksploatacija – korak po korak

Pokrenite aplikaciju s `python -m vulnshop` (host `http://localhost:8000`). Zahtjevi su u `http/lab08.http`; za slanje recenzije možete koristiti i **Swagger UI** na `http://localhost:8000/docs`. Na Linuxu/macOS-u umjesto `curl.exe` pišete `curl`.

> Ove odgovore najbolje je otvoriti u **pregledniku** — REST klijent ili Swagger prikazuju HTML kao tekst i neće izvršiti skriptu.

1. **Reflektirani XSS:** otvorite u pregledniku

   ```
   http://localhost:8000/lab08/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E
   ```

   (`q = <script>alert(document.cookie)</script>`) **Očekivano (ranjivo):** iskoči `alert` s kolačićem; u izvoru stranice vidi se nekodirani `<script>alert(document.cookie)</script>`.
2. **Pohranjeni XSS:** spremite zlonamjernu recenziju

   ```
   curl.exe -s -X POST http://localhost:8000/api/lab08/reviews -H "Content-Type: application/json" -d "{\"productId\":1,\"author\":\"napadac\",\"text\":\"<img src=x onerror=alert('XSS')>\"}"
   ```

   Zatim otvorite `http://localhost:8000/lab08/products/1/reviews` u pregledniku. **Očekivano (ranjivo):** `onerror` se izvrši pri svakom učitavanju stranice; u izvoru je nekodirani `<img src=x onerror=alert('XSS')>`.

## 5. Analiza uzroka

```python
# RANJIVO: reflektirani XSS – q se upisuje izravno u HTML.
html = PAGE_START.format(title="Pretraga") + "<h1>Rezultati pretrage za: " + q + "</h1>" + PAGE_END
...
# RANJIVO: pohranjeni XSS – author i text upisuju se izravno u HTML.
html += '<div class="review"><strong>' + row["author"] + "</strong>: " + row["text"] + "</div>"
```

Izlaz se ne kodira za HTML kontekst, pa preglednik unesene oznake tumači kao kod.

## 6. Popravak

- Kontekstualno kodiranje izlaza: svaki korisnički podatak prođe kroz `html.escape(...)` prije upisa u HTML (`<` → `&lt;`, `"` → `&quot;` …).
- Validacija ulaza — duljina autora i teksta preko Pydantic `Field(min_length=..., max_length=...)`.
- Zaglavlje `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'` kao drugi sloj obrane (blokira inline skripte).
- Napomena: predlošci s automatskim escapeanjem (Jinja2 uz `autoescape=True`, Django) kodiraju sami; opasni su `|safe`, `Markup(...)` i isključen `autoescape`.

<details>
<summary>Referentno rješenje (grana <code>rjesenja</code>)</summary>

```python
CSP = "default-src 'self'; script-src 'self'; object-src 'none'"

def html_page(content: str) -> HTMLResponse:
    return HTMLResponse(content, headers={"Content-Security-Policy": CSP})

@router.get("/lab08/search", response_class=HTMLResponse)
def search(q: str = ""):
    body = "<h1>Rezultati pretrage za: " + html.escape(q) + "</h1>"   # POPRAVAK: kodiranje izlaza
    return html_page(PAGE_START.format(title="Pretraga") + body + PAGE_END)

class ReviewRequest(BaseModel):
    product_id: int = Field(alias="productId")
    author: str = Field(min_length=1, max_length=100)     # POPRAVAK: validacija ulaza
    text: str = Field(min_length=1, max_length=2000)

@router.get("/lab08/products/{product_id}/reviews", response_class=HTMLResponse)
def reviews(product_id: int, db: DbDep):
    rows = db.query("SELECT author, text FROM lab08_reviews WHERE product_id = ? ORDER BY id", (product_id,))
    page = PAGE_START.format(title="Recenzije") + f"<h1>Recenzije za proizvod {product_id}</h1>"
    for row in rows:
        page += f'<div class="review"><strong>{html.escape(row["author"])}</strong>: {html.escape(row["text"])}</div>'
    return html_page(page + PAGE_END)
```

</details>

## 7. Provjera popravka

### a) Testovi

```
pytest -m lab08
pytest -m "lab08 and security"
```

IDE: u PyCharmu kliknite zeleni ▶ pokraj testne funkcije (ili desni klik na `tests/lab08` → *Run 'pytest in lab08'*); u VS Codeu otvorite panel *Testing* (ikona tikvice) i pokrenite `tests/lab08`.

- **Prije popravka** padaju: `test_reflected_xss_is_encoded`, `test_stored_xss_is_encoded`, `test_csp_header_with_script_src`.
- **Poslije popravka** svi prolaze: payload je u HTML-u kodiran (`&lt;script&gt;…`, `&lt;img …`), a odgovor nosi zaglavlje `Content-Security-Policy` sa `script-src`. Funkcionalni (`test_plain_search_shows_term`, `test_plain_review_is_saved_and_shown`) prolaze na obje grane.

### b) Ponovljeni napad

Ponovite oba napada u pregledniku: skripta se više ne izvršava, a u izvoru stranice stoji kodirani oblik (`&lt;script&gt;…`). Prazan autor ili tekst duži od 2000 znakova sada vraća `400` (Pydantic validacija).

### c) Ponovno skeniranje

Dinamički: **OWASP ZAP** (*passive* + *active scan* prepoznaje reflektirani XSS) ili **Burp** Repeater nad parametrom `q`. Statički:

```
semgrep scan --config p/python
```

(obrasce građenja HTML-a konkatenacijom).

## 8. Zadatak za samostalni rad

- Prebacite prikaz recenzija na Jinja2 predložak (`autoescape=True`) umjesto ručne konkatenacije i **napišite dodatni pytest test** koji dokazuje da je predložak automatski kodirao `<script>` iz pohranjene recenzije (bez poziva `html.escape`).

**Pitanja za razmišljanje:**
1. Koja je razlika između HTML, atributnog i JavaScript konteksta kodiranja?
2. Zašto je CSP „defense in depth“, a ne zamjena za kodiranje izlaza?
3. Što je DOM-based XSS i zašto ga kodiranje na poslužitelju ne pokriva?
