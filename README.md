# VulnShop Akademija (Python / FastAPI)

Namjerno **ranjiva** web trgovina za vježbe sigurnog programiranja u sklopu mikrokvalifikacije
**„Implementacija sigurnosnih mehanizama u programskoj podršci"** (Span Centar kibernetičke sigurnosti,
Koturaška 47, Zagreb). Predavač: doc. dr. sc. Aleksander Radovan.

> ⚠️ **UPOZORENJE:** Ova aplikacija sadrži namjerne sigurnosne propuste (SQL injection, XSS, SSRF,
> nesigurna deserijalizacija i dr.). Služi **isključivo za edukaciju**. Pokrećite je **samo lokalno**
> i **nikada** je ne izlažite na javnu mrežu ni produkciju.

Iste vježbe, URL-ovi i seed podaci postoje i u paralelnim verzijama:

- **Java / Spring Boot:** <https://github.com/aradovanJava/secure-coding-akademija-java>
- **C# / .NET:** <https://github.com/aradovanJava/secure-coding-akademija-dotnet>

## Način rada: „crveno → zeleno"

Program traži da za svaku ranjivost polaznik: (1) pronađe ranjivost alatom, (2) analizira uzrok,
(3) ispravi je, (4) ponovnim testom/skeniranjem potvrdi da je otklonjena i (5) **napiše jedinični test**.

Zato je svaka vježba organizirana kao **crveno → zeleno**:

- **Sigurnosni testovi** (`@pytest.mark.security`) na grani `main` **PADAJU** — to je dokaz da ranjivost postoji.
- Nakon ispravnog popravka (grana `rjesenja`) ti isti testovi **PROLAZE**.
- **Funkcionalni testovi** (`@pytest.mark.functional`) prolaze **uvijek** — dokaz da popravak ne lomi legitimno ponašanje.

## Grane

| Grana | Sadržaj |
|---|---|
| `main` | Ranjiva aplikacija + sigurnosni testovi (padaju) + funkcionalni testovi (prolaze) + sve upute. |
| `rjesenja` | Ista aplikacija s ispravcima svih 15 ranjivosti; **svi** testovi prolaze. |

Upute u grani `main` već sadrže smjernice za popravak (u bloku *„Referentno rješenje"*), a cjeloviti ispravljeni
kod je u grani `rjesenja`. Nakon prelaska na drugu granu ponovno pokrenite `pip install -r requirements-dev.txt`
(grane imaju različitu verziju paketa `jinja2` – vidi Lab05).

## Preduvjeti

- **Python 3.12 ili noviji** (testirano na 3.12, 3.13 i 3.14)
- **Git**
- IDE: **PyCharm** ili **VS Code** (proširenja Python + REST Client)

Detaljne upute za postavljanje: [`docs/00-postavljanje-okruzenja.md`](docs/00-postavljanje-okruzenja.md).

## Brzi početak

```bash
# 1. Kloniraj
git clone https://github.com/aradovanJava/secure-coding-akademija-python.git
cd secure-coding-akademija-python

# 2. Virtualno okruženje i ovisnosti
python -m venv .venv
# Windows (PowerShell):  .\.venv\Scripts\Activate.ps1
# Linux / macOS:         source .venv/bin/activate
pip install -r requirements-dev.txt

# 3. Pokreni aplikaciju (http://localhost:8000, Swagger UI na http://localhost:8000/docs)
python -m vulnshop

# 4. U drugom terminalu – prijava (dobivaš token)
curl -s -X POST http://localhost:8000/api/auth/login -H "Content-Type: application/json" -d "{\"username\":\"ana\",\"password\":\"Ana123!\"}"
```

Na Windowsu u PowerShellu koristite `curl.exe` (ne alias `curl`) – vidi upute za okruženje.

Pokretanje testova po skupinama (pytest oznake):

```bash
pytest -m functional              # svi funkcionalni (uvijek zeleni)
pytest -m security                # svi sigurnosni (na main padaju, na rjesenja prolaze)
pytest -m lab01                   # samo vježba 01 (sigurnosni + funkcionalni)
pytest -m "lab07 and security"    # samo sigurnosni testovi vježbe 07
pytest --cov=vulnshop --cov-report=term-missing   # pokrivenost koda testovima
```

## Prijava i korisnici

Zajednička autentikacija (`POST /api/auth/login`) vraća nasumičan token koji se šalje kao
`Authorization: Bearer <token>` (u Swagger UI-ju: gumb **Authorize**). Seed korisnici:

| Korisničko ime | Lozinka | Uloga |
|---|---|---|
| `ana` | `Ana123!` | USER |
| `marko` | `Marko123!` | USER |
| `admin` | `Admin123!` | ADMIN |

Lozinke su u bazi pohranjene **sigurno** (Argon2id) — autentikacija nije dio vježbi.

## Pregled 15 vježbi (OWASP Top 10:2025)

| Lab | Kategorija | CWE | Endpoint(i) | Uputa |
|---|---|---|---|---|
| 01 | A01 Broken Access Control (IDOR) | CWE-639 | `GET /api/lab01/orders/{id}` | [lab01](docs/labs/lab01-idor.md) |
| 02 | A01 (Mass assignment) | CWE-915, 269 | `PUT /api/lab02/profile`, `GET /api/lab02/admin/users` | [lab02](docs/labs/lab02-mass-assignment.md) |
| 03 | A01 (SSRF) | CWE-918 | `GET /api/lab03/preview?url=` | [lab03](docs/labs/lab03-ssrf.md) |
| 04 | A02 Security Misconfiguration | CWE-16, 209, 942, 693 | `GET /api/lab04/ping`, `/crash`, `/debug/config` | [lab04](docs/labs/lab04-misconfiguration.md) |
| 05 | A03 Software Supply Chain Failures | CWE-1104, 1395 | `POST /api/lab05/greeting` | [lab05](docs/labs/lab05-supply-chain.md) |
| 06 | A04 Cryptographic Failures | CWE-916, 327, 321, 329 | `POST /api/lab06/register`, `/cards` | [lab06](docs/labs/lab06-crypto.md) |
| 07 | A05 Injection (SQLi) | CWE-89 | `GET /api/lab07/products/search`, `POST /api/lab07/login` | [lab07](docs/labs/lab07-sql-injection.md) |
| 08 | A05 Injection (XSS) | CWE-79 | `GET /lab08/search`, `POST /api/lab08/reviews` | [lab08](docs/labs/lab08-xss.md) |
| 09 | A05 Injection (OS command) | CWE-78 | `GET /api/lab09/ping?host=` | [lab09](docs/labs/lab09-command-injection.md) |
| 10 | A06 Insecure Design | CWE-840, 20 | `POST /api/lab10/checkout`, `GET /api/lab10/wallet` | [lab10](docs/labs/lab10-insecure-design.md) |
| 11 | A07 Authentication Failures (brute force) | CWE-307, 204 | `POST /api/lab11/login` | [lab11](docs/labs/lab11-brute-force.md) |
| 12 | A07 (JWT propusti) | CWE-347, 798, 613 | `POST /api/lab12/login`, `GET /api/lab12/me`, `/admin` | [lab12](docs/labs/lab12-jwt.md) |
| 13 | A08 Software/Data Integrity Failures | CWE-502 | `POST /api/lab13/cart/import` | [lab13](docs/labs/lab13-deserijalizacija.md) |
| 14 | A09 Logging & Alerting Failures | CWE-778, 117, 532 | `POST /api/lab14/login` | [lab14](docs/labs/lab14-logging.md) |
| 15 | A10 Mishandling of Exceptional Conditions | CWE-636, 755, 209, 460 | `POST /api/lab15/transfer`, `GET /api/lab15/accounts` | [lab15](docs/labs/lab15-iznimke.md) |

## Struktura repozitorija

```
secure-coding-akademija-python/
├─ vulnshop/
│  ├─ __main__.py                     # pokretanje: python -m vulnshop (port 8000)
│  ├─ app.py                          # create_app(): aplikacija sa svježom bazom
│  ├─ config.py                       # postavke iz okoline (lab04 i lab12 ranjive na main)
│  ├─ common/                         # baza, prijava, pomoćne funkcije (ISPRAVNO, nije vježba)
│  └─ lab01 … lab15/                  # routes.py (kod vježbe), data.py (tablice i seed)
├─ tests/
│  ├─ conftest.py                     # zajednički fixturei (client, auth, live_server)
│  ├─ lab01 … lab15/                  # test_labXX_security.py + test_labXX_functional.py
│  └─ lab13/payloads.py               # pomoćni alat za Base64 sadržaj (python -m tests.lab13.payloads)
├─ docs/                              # upute (00 okruženje, 01 alati, labs/)
├─ http/                              # .http datoteke (VS Code REST Client / PyCharm HTTP Client)
├─ wordlists/top-100.txt
├─ requirements.txt                   # izvršne ovisnosti (zaključane verzije)
├─ requirements-dev.txt               # + pytest, Bandit, Ruff, pip-audit, CycloneDX
├─ pyproject.toml                     # pytest oznake, Ruff i Bandit postavke
├─ run.py                             # pokretanje iz IDE-a (desni klik → Run)
├─ scripts/ci_summary.py              # sažetak po vježbi za CI anotacije
└─ .github/workflows/ci.yml
```

## Alati Tjedna 1

Pregled profesionalnih alata (OWASP ZAP, Burp Suite, Semgrep, Bandit, Ruff, pip-audit, OSV-Scanner,
Trivy, CycloneDX) s konkretnim naredbama nad ovom aplikacijom: [`docs/01-alati.md`](docs/01-alati.md).
