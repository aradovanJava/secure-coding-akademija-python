# Lab07 – SQL injection

## 1. Cilj vježbe

Pokazati klasičnu SQL injekciju kroz spajanje korisničkog unosa u tekst upita (pretraga proizvoda i prijava)
te je ispraviti parametriziranim upitima.

- **OWASP Top 10:2025:** A05 – Injection
- **CWE:** CWE-89 (*SQL Injection*)

## 2. Gdje je kod

- `vulnshop/lab07/routes.py`
  - funkcija `search_products(q, db)` → `GET /api/lab07/products/search?q=`
  - funkcija `login(body, db)` → `POST /api/lab07/login`
- Podaci: `vulnshop/lab07/data.py` — `lab07_products` (vidljivi Laptop/Miš/Tipkovnica/Monitor + skriveni „Interni prototip X“) i `lab07_accounts` (lozinke u čistom tekstu, **namjerno**, za UNION napad).
- Testovi: `tests/lab07/test_lab07_security.py`, `tests/lab07/test_lab07_functional.py`.

## 3. Opis ranjivosti

Pretraga gradi upit f-stringom:

```
SELECT ... FROM lab07_products WHERE hidden = 0 AND name LIKE '%<q>%'
```

Prijava jednako tako: `... WHERE username = '<u>' AND password = '<p>'`. Korisnički unos postaje dio SQL *koda*, a ne ostaje podatak, pa napadač može promijeniti strukturu upita.

## 4. Eksploatacija – korak po korak

Pokrenite aplikaciju s `python -m vulnshop` (host `http://localhost:8000`). Zahtjevi su u `http/lab07.http` (koristite URL-enkodirane oblike iz te datoteke); isto možete izvesti i kroz **Swagger UI** na `http://localhost:8000/docs`. Na Linuxu/macOS-u umjesto `curl.exe` pišete `curl`.

1. **Skriveni proizvodi:** `q = ' OR '1'='1' --`

   ```
   GET /api/lab07/products/search?q=%27%20OR%20%271%27%3D%271%27%20--
   ```

   Nastali upit:

   ```sql
   SELECT id, name, description, price FROM lab07_products
   WHERE hidden = 0 AND name LIKE '%' OR '1'='1' --%'
   ```

   `AND` ima prednost pred `OR`, pa je uvjet `(hidden = 0 AND ...) OR '1'='1'` — istinit za **svaki** redak.
   **Očekivano (ranjivo):** u rezultatima se pojavi „Interni prototip X“. Varijanta `%' OR 1=1 --` daje isti učinak.

   > **Zašto `--` na kraju?** Bez komentara (`%' OR '1'='1`) ostaje višak `%'` iz izvornog upita, pa nastaje uvjet `'1'='1%'`, koji je **lažan** — vrate se samo 4 vidljiva proizvoda, skriveni se ne pojavi. Zato napadač ostatak naredbe „zakomentira“. Isprobajte obje varijante i usporedite odgovore.
2. **UNION — izvlačenje računa:** `q = %' UNION SELECT id, username, password, 0 FROM lab07_accounts --`

   ```
   GET /api/lab07/products/search?q=%25%27%20UNION%20SELECT%20id%2C%20username%2C%20password%2C%200%20FROM%20lab07_accounts%20--
   ```

   **Očekivano (ranjivo):** u polju `name`/`description` pojave se `admin`/`SuperTajna2026` i `webshop`/`Shop!2026`.
3. **Zaobilazak prijave:** `username = admin'--`, bilo koja lozinka:

   ```
   curl.exe -s -X POST http://localhost:8000/api/lab07/login -H "Content-Type: application/json" -d "{\"username\":\"admin'--\",\"password\":\"bilosto\"}"
   ```

   **Očekivano (ranjivo):** `200` i `{"status":"prijavljen","username":"admin"}` — lozinka se preskače jer je `--` zakomentirao dio `AND password = '...'`.

## 5. Analiza uzroka

```python
# RANJIVO: q se umeće izravno u tekst SQL upita.
sql = f"SELECT id, name, description, price FROM lab07_products WHERE hidden = 0 AND name LIKE '%{q}%'"
...
# RANJIVO: korisničko ime i lozinka umeću se izravno u SQL.
sql = f"SELECT id, username FROM lab07_accounts WHERE username = '{username}' AND password = '{password}'"
```

Korisnički unos postaje dio naredbe umjesto da se bazi preda kao parametar.

## 6. Popravak

- Parametrizirani upiti s `?` placeholderima (modul `sqlite3`) — baza unos nikad ne tumači kao SQL.
- Za `LIKE` escapeajte zamjenske znakove `%`, `_` i `\` uz `ESCAPE '\'`.
- Ograničite duljinu unosa.
- Obrana u dubinu: ORM (SQLAlchemy — `text()` s vezanim parametrima ili ORM sloj) parametrizira automatski; DB korisnik neka ima najmanje potrebne ovlasti (*least privilege*), da UNION na druge tablice ne uspije.

<details>
<summary>Referentno rješenje (grana <code>rjesenja</code>)</summary>

```python
MAX_QUERY_LENGTH = 100

def escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

@router.get("/api/lab07/products/search")
def search_products(q: str, db: DbDep):
    if len(q) > MAX_QUERY_LENGTH:
        return error(400, "Pojam za pretragu je predugačak.")
    rows = db.query(
        "SELECT id, name, description, price FROM lab07_products WHERE hidden = 0 AND name LIKE ? ESCAPE '\\'",
        (f"%{escape_like(q)}%",),
    )
    return [{**row, "price": to_money(row["price"])} for row in rows]

@router.post("/api/lab07/login")
def login(body: LoginRequest, db: DbDep):
    row = db.query_one(
        "SELECT id, username FROM lab07_accounts WHERE username = ? AND password = ?",
        (body.username or "", body.password or ""),
    )
    if row is None:
        return error(401, "Neispravni podaci.")
    return {"status": "prijavljen", "username": row["username"]}
```

</details>

## 7. Provjera popravka

### a) Testovi

```
pytest -m lab07
pytest -m "lab07 and security"
```

IDE: u PyCharmu kliknite zeleni ▶ pokraj testne funkcije (ili desni klik na `tests/lab07` → *Run 'pytest in lab07'*); u VS Codeu otvorite panel *Testing* (ikona tikvice) i pokrenite `tests/lab07`.

- **Prije popravka** padaju: `test_or_injection_does_not_reveal_hidden_product`, `test_union_does_not_reveal_accounts`, `test_login_bypass_is_rejected`.
- **Poslije popravka** svi prolaze: skriveni proizvod se ne pojavljuje, UNION vrati praznu listu, `admin'--` → `401`. Funkcionalni (`test_search_laptop_returns_one_result` → 1 rezultat; `test_valid_login` → 200) prolaze na obje grane.

### b) Ponovljeni napad

Nakon popravka `' OR '1'='1' --` i UNION payload vraćaju `[]` (prazna lista), a prijava `admin'--` vraća `401 {"error":"Neispravni podaci."}`. Legitimna pretraga `q=Laptop` i prijava `admin`/`SuperTajna2026` i dalje rade.

### c) Ponovno skeniranje

```
bandit -c pyproject.toml -r vulnshop
ruff check vulnshop --select S
semgrep scan --config p/python
```

Na grani `main` Bandit (`B608`) i Ruff (`S608`) prijavljuju SQL građen stringom u `lab07/routes.py` (dvije lokacije); nakon prelaska na parametrizirane upite tih nalaza nema. Dinamički: **OWASP ZAP** aktivni scan ili **Burp** Repeater/Intruder nad parametrom `q`.

## 8. Zadatak za samostalni rad

- Dodajte parametar `max_price` pretrazi i implementirajte ga **parametrizirano**; zatim **napišite dodatni pytest test** koji dokazuje da injekcija kroz `max_price` (npr. `max_price=0 OR 1=1`) ne otkriva skrivene proizvode.

**Pitanja za razmišljanje:**
1. Zašto parametrizacija pobjeđuje ručni „escaping“ ulaza?
2. Kako biste ograničili DB korisnika (*least privilege*) tako da UNION na druge tablice ne uspije?
3. Zašto lozinke u `lab07_accounts` nikad ne bi smjele biti u čistom tekstu (vidi Lab06)?
