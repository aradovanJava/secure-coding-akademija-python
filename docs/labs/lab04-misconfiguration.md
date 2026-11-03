# Lab04 – Security Misconfiguration

## 1. Cilj vježbe

Prepoznati niz pogrešnih konfiguracija: uključen *debug* način koji vraća cijeli traceback, dijagnostički
endpoint koji otkriva tajne, prepopustljiv CORS i nedostatak sigurnosnih zaglavlja. Polaznik ih zatvara kroz
konfiguraciju i *middleware*.

- **OWASP Top 10:2025:** A02 – Security Misconfiguration
- **CWE:** CWE-16, CWE-209 (*Information Exposure Through an Error Message*), CWE-942 (*Permissive CORS*), CWE-693 (*Protection Mechanism Failure*)

## 2. Gdje je kod

- Postavke: `vulnshop/config.py` – `Settings.debug` (okolina `APP_DEBUG`, **zadano `True` na `main`**),
  `cors_allowed_origins`, `payment_api_key`, `lab12_jwt_secret`.
- `vulnshop/app.py` – `FastAPI(debug=settings.debug, ...)`.
- `vulnshop/lab04/security_config.py` – CORS i (na `rjesenja`) sigurnosna zaglavlja i generički rukovatelj
  greškom.
- `vulnshop/lab04/routes.py` – `GET /api/lab04/ping`, `GET /api/lab04/crash`, `GET /api/lab04/debug/config`.
- Testovi: `tests/lab04/test_lab04_security.py` i `tests/lab04/test_lab04_functional.py`.

> FastAPI nema Spring Bootov *actuator*; zdravstveni endpoint je `GET /health`. Endpoint
> `/api/lab04/debug/config` je ovdje analogon izloženom `/actuator/env`.

## 3. Opis ranjivosti

Na grani `main`:

- `APP_DEBUG` je po zadanom `True` → `FastAPI(debug=True)` → Starlette za svaku neobrađenu iznimku vraća
  **cijeli Python traceback** (putanje, nazive modula i klasa, dijelove koda).
- `GET /api/lab04/debug/config` javno vraća sve postavke, uključujući `payment_api_key`
  (`sk_live_akademija_123`) i Lab12 JWT tajnu (`secret123`), plus verziju Pythona i radni direktorij.
- CORS je `allow_origin_regex=".*"` uz `allow_credentials=True` → bilo koja stranica može slati
  autentificirane zahtjeve i čitati odgovore (specifikacija zabranjuje `*` + vjerodajnice, pa se origin
  **reflektira**).
- Nema sigurnosnih zaglavlja (`X-Content-Type-Options`, `X-Frame-Options`, CSP, `Referrer-Policy`).

## 4. Eksploatacija – korak po korak

Pokrenite aplikaciju s `python -m vulnshop` (host `http://localhost:8000`). Gotovi zahtjevi su u
`http/lab04.http`; iste pozive možete izvesti i kroz **Swagger UI** na `http://localhost:8000/docs`. Na
Linuxu/macOS-u umjesto `curl.exe` pišete `curl`. Ovi endpointi ne traže prijavu.

1. **Tajne iz dijagnostike:**
   ```
   curl.exe -s http://localhost:8000/api/lab04/debug/config
   ```
   **Očekivano (ranjivo):** `200` i cijela konfiguracija, npr.
   `"payment_api_key":"sk_live_akademija_123"`, `"lab12_jwt_secret":"secret123"`.
2. **Traceback u odgovoru:**
   ```
   curl.exe -s http://localhost:8000/api/lab04/crash
   ```
   **Očekivano (ranjivo):** `500` i `text/plain` traceback s `Traceback (most recent call last)`,
   `RuntimeError`, `sqlite3`, `vulnshop/lab04/routes.py` i putanjama datoteka.
3. **CORS** – preflight sa zlonamjernog origina (vidi `http/lab04.http`):
   ```
   curl.exe -s -i -X OPTIONS http://localhost:8000/api/lab04/ping -H "Origin: https://evil.example" -H "Access-Control-Request-Method: GET"
   ```
   **Očekivano (ranjivo):** odgovor sadrži `access-control-allow-origin: https://evil.example` i
   `access-control-allow-credentials: true`.
4. **Sigurnosna zaglavlja:** `GET /api/lab04/ping` — u odgovoru **nema** `X-Content-Type-Options`,
   `X-Frame-Options` ni CSP. Pasivni *scan* u **OWASP ZAP**-u odmah to prijavljuje.

## 5. Analiza uzroka

```python
# config.py – RANJIVO: debug je uključen i u "produkciji".
debug: bool = field(default_factory=lambda: _env_bool("APP_DEBUG", True))

# lab04/security_config.py – RANJIVO: refleksija bilo kojeg origina uz vjerodajnice.
app.add_middleware(CORSMiddleware, allow_origin_regex=".*", allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

# lab04/routes.py – RANJIVO: dijagnostički endpoint otkriva sve postavke s tajnama.
return {"settings": asdict(request.app.state.settings), "python": sys.version, ...}
```

Konfiguracija izlaže detalje grešaka i sve postavke, CORS reflektira svaki origin, a sigurnosnih zaglavlja
nema. Ranjivost je u konfiguraciji, ne u poslovnom kodu.

## 6. Popravak

- `APP_DEBUG` po zadanom **`False`** („*secure by default*“); uključuje se svjesno samo za lokalni razvoj.
- Uklonite dijagnostički endpoint `/api/lab04/debug/config` (u produkciji dijagnostika samo iza autentikacije
  i/ili u razvojnom okruženju).
- CORS allowlista iz konfiguracije (`CORS_ALLOWED_ORIGINS`), bez `*`.
- *Middleware* sa sigurnosnim zaglavljima: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Content-Security-Policy: default-src 'self'`, `Referrer-Policy: no-referrer`. CSP se **ne** stavlja na
  `/docs` (Swagger UI učitava skripte s CDN-a); u produkciji dokumentaciju isključite
  (`FastAPI(docs_url=None, redoc_url=None)`) ili je zaštitite prijavom.
- Generički rukovatelj za neočekivanu grešku: **RFC 9457** `application/problem+json` s `correlationId`;
  detalji ostaju samo u logu poslužitelja.

> *Debug* se prebacuje varijablom okoline (`APP_DEBUG=true` za lokalni razvoj). U VS Codeu za to postoji
> konfiguracija pokretanja **„VulnShop (rjesenja: produkcijski nacin, APP_DEBUG=false)“** (`.vscode/launch.json`).

<details>
<summary>Referentno rješenje (grana <code>rjesenja</code>)</summary>

```python
# config.py – POPRAVAK: "secure by default".
debug: bool = field(default_factory=lambda: _env_bool("APP_DEBUG", False))

# lab04/security_config.py
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'self'",
    "Referrer-Policy": "no-referrer",
}
DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")


def init(app: FastAPI) -> None:
    settings = app.state.settings
    # POPRAVAK: CORS allowlista iz konfiguracije.
    app.add_middleware(
        CORSMiddleware, allow_origins=settings.cors_allowed_origins, allow_credentials=True,
        allow_methods=["GET", "POST", "PUT"], allow_headers=["Authorization", "Content-Type"],
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            if name == "Content-Security-Policy" and request.url.path.startswith(DOCS_PATHS):
                continue  # Swagger UI učitava skripte s CDN-a
            response.headers.setdefault(name, value)
        return response

    @app.exception_handler(Exception)
    async def unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
        correlation_id = str(uuid.uuid4())
        log.error("Neobrađena greška correlationId=%s path=%s", correlation_id, request.url.path, exc_info=exc)
        return JSONResponse(status_code=500, media_type="application/problem+json", content={
            "type": "about:blank", "title": "Interna greška poslužitelja", "status": 500,
            "detail": "Došlo je do neočekivane greške. Pokušajte ponovno kasnije.",
            "correlationId": correlation_id,
        })
```

Dijagnostički endpoint `/api/lab04/debug/config` u `routes.py` je uklonjen.

</details>

## 7. Provjera popravka

### a) Testovi

```
pytest -m lab04
pytest -m "lab04 and security"
```

U PyCharmu: zeleni ▶ pokraj testne funkcije ili desni klik na `tests/lab04` → *Run 'pytest in lab04'*. U VS
Codeu: panel **Testing** (ikona tikvice/*flask*).

- **Prije popravka** padaju: `test_debug_config_endpoint_is_not_exposed` (endpoint vraća tajne),
  `test_crash_returns_500_without_traceback` (traceback u odgovoru), `test_cors_does_not_allow_evil_origin`
  (reflektira evil origin), `test_ping_has_security_headers` (nema zaglavlja).
- **Poslije popravka** svi prolaze; funkcionalni `test_health_is_available` i `test_ping_works` prolaze na obje
  grane.

> Testovi se izvode sa zadanim `APP_DEBUG` (na `rjesenja` je to `False`). Ako na grani `rjesenja` ručno
> postavite `APP_DEBUG=true`, `test_crash_returns_500_without_traceback` će **pasti** — Starlette tada opet
> prikazuje traceback. To je očekivano i upravo je razlog zašto je produkcijski način „secure by default“.

### b) Ponovljeni napad

`/api/lab04/debug/config` → **404** `{"error":"Not Found"}` (bez tajni); `/api/lab04/crash` → **500**
`application/problem+json` s `correlationId`, bez tracebacka; CORS preflight s `https://evil.example` →
`400 Disallowed CORS origin` (nema `access-control-allow-origin`), dok dopušteni `http://localhost:3000`
prolazi; `/api/lab04/ping` sada nosi `x-content-type-options: nosniff` i `x-frame-options: DENY`.

### c) Ponovno skeniranje

- **OWASP ZAP** pasivni *scan*: nestaju upozorenja o nedostatku `X-Content-Type-Options`, `X-Frame-Options` i
  CSP; nema više reflektiranog origina.
- **Ruff** na grani `main` prijavljuje hardkodiranu tajnu `S105` (`lab12_jwt_secret` u `config.py`) — povezano
  s Lab12; **Bandit** ne prijavljuje ništa u lab04. Misconfiguration je uglavnom izvan dosega SAST-a, pa
  vrijede testovi i *scan*.

## 8. Zadatak za samostalni rad

- Dodajte zaglavlja `Strict-Transport-Security` i `Permissions-Policy` u `SECURITY_HEADERS` i **napišite
  dodatni pytest test** koji provjerava njihovu prisutnost u odgovoru na `GET /api/lab04/ping`.

**Pitanja za razmišljanje:**
1. Zašto je opasno u produkciji ostaviti uključen *debug* i dijagnostičke endpointe (npr. `/actuator/env`)?
2. Zašto `Access-Control-Allow-Origin: *` i `allow_credentials=True` zajedno nisu dopušteni po specifikaciji?
3. Što je *correlation ID* i kako pomaže da poruku o grešci klijentu učinimo generičnom, a da i dalje možemo
   istražiti incident?
