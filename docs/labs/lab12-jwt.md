# Lab12 – JWT propusti

## 1. Cilj vježbe

Pokazati tri klasična JWT propusta u ručno napisanom verifikatoru: prihvaćanje `alg:none`, slaba
hardkodirana tajna i neprovjeravanje isteka (`exp`). Polaznik uvodi allowlistu algoritma, usporedbu potpisa u
konstantnom vremenu, jaku tajnu iz konfiguracije i provjeru `exp`.

- **OWASP Top 10:2025:** A07 – Authentication Failures
- **CWE:** CWE-347 (Improper Verification of Cryptographic Signature), CWE-798 (Use of Hard-coded Credentials), CWE-613 (Insufficient Session Expiration)

## 2. Gdje je kod

- `vulnshop/lab12/jwt_service.py` – klasa `JwtService` (ručni HS256); metode `create_token(username, role,
  expires_at)` i **ranjivi** `verify(token)`.
- `vulnshop/lab12/routes.py` → endpointi `POST /api/lab12/login`, `GET /api/lab12/me`, `GET /api/lab12/admin`.
- `vulnshop/lab12/data.py` – stvara `JwtService` s tajnom iz konfiguracije (dostupan kao
  `app.state.lab12_jwt`).
- Tajna: `vulnshop/config.py`, polje `lab12_jwt_secret` (`secret123` na `main`; jaka, iz okoline
  `LAB12_JWT_SECRET`, na `rjesenja`).
- Testovi: `tests/lab12/test_lab12_security.py` i `tests/lab12/test_lab12_functional.py`.

> Napomena: ova vježba **ne** koristi zajednički token iz `/api/auth/login`, nego vlastiti JWT u istom
> zaglavlju `Authorization: Bearer <jwt>`.

## 3. Opis ranjivosti

Ranjivi `verify(token)`:

- čita `alg` iz **zaglavlja tokena** i ako je `none`, **preskače** provjeru potpisa,
- potpis uspoređuje operatorom `==` (vrijeme usporedbe ovisi o sadržaju – nije konstantno),
- **ne** provjerava `exp`, pa istekli token i dalje prolazi.

Tajna `secret123` je slaba i nalazi se u wordlisti, pa se potpisani token može razbiti *offline*.

## 4. Eksploatacija – korak po korak

> Pokreni aplikaciju s `python -m vulnshop` (`http://localhost:8000`, Swagger UI na
> `http://localhost:8000/docs`). Gotovi zahtjevi su u `http/lab12.http`. Na Linuxu/macOS-u umjesto `curl.exe`
> pišeš `curl`.

1. **alg:none:** pošalji token s headerom `{"alg":"none"}`, payloadom `{"role":"ADMIN",...}` i **praznim**
   potpisom na `GET /api/lab12/admin`. Gotov token je u `http/lab12.http`:
   ```bash
   curl.exe -s http://localhost:8000/api/lab12/admin -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJuYXBhZGFjIiwicm9sZSI6IkFETUlOIiwiaWF0IjowLCJleHAiOjk5OTk5OTk5OTl9."
   ```
   **Očekivano (ranjivo):** **200** `{"status":"admin ok","sub":"napadac"}` – napadač je dobio ADMIN pristup
   bez poznavanja tajne.
2. **Slaba tajna (offline crack):** spremi presretnuti HS256 token u `token.txt` i razbij tajnu:
   ```bash
   hashcat -m 16500 token.txt wordlists/top-100.txt
   ```
   (`secret123` je u listi.) Zatim alatom `jwt_tool` ili na `jwt.io` krivotvori token s `role:ADMIN`,
   potpisan pronađenom tajnom, i pošalji ga na `/admin`. **Očekivano (ranjivo):** **200** `{"status":"admin
   ok",...}`.
3. **Istekli token:** token s prošlim `exp` i dalje prolazi na `GET /api/lab12/me`. **Očekivano (ranjivo):**
   **200** (umjesto 401), jer se `exp` ne provjerava.

## 5. Analiza uzroka

```python
# RANJIVO: algoritam određuje napadač – "none" preskače provjeru potpisa.
if str(header.get("alg", "")).lower() != "none":
    if len(parts) != 3:
        return None
    expected = b64url_encode(hmac_sha256(parts[0] + "." + parts[1], self._secret))
    # RANJIVO: obična usporedba stringova (nije u konstantnom vremenu).
    if expected != parts[2]:
        return None
# RANJIVO: exp se ne provjerava.
return payload
```

Povjerenje u `alg` iz zaglavlja znači da **napadač bira** hoće li se potpis uopće provjeriti. Usporedba `==`
curi informaciju kroz vrijeme izvođenja (*timing side-channel*). Izostanak provjere `exp` čini tokene vječnima.
Uz slabu, hardkodiranu tajnu (`secret123` u `config.py`) i treći napad (offline crack) postaje trivijalan.

## 6. Popravak

- Allowlista algoritma: prihvaćaj **samo HS256**; algoritam određuje poslužitelj, a ne zaglavlje tokena.
- Usporedba potpisa u konstantnom vremenu (`hmac.compare_digest`).
- Provjera `exp` (token je obavezno vremenski ograničen); po želji i `iss`/`aud`.
- Jaka 256-bitna tajna iz okoline `LAB12_JWT_SECRET` (na `rjesenja`, ako nije zadana, generira se nasumična
  po pokretanju – vidi `config.py`).
- Preporuka: u stvarnim projektima koristi provjerenu biblioteku (**PyJWT**, **joserfc**, **Authlib**) i
  eksplicitno zadaj dopuštene algoritme, npr. `jwt.decode(token, key, algorithms=["HS256"])`.

<details>
<summary>Referentno rješenje (grana <code>rjesenja</code>)</summary>

```python
ALLOWED_ALGORITHM = "HS256"

def verify(self, token: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return None
        # POPRAVAK: algoritam određuje POSLUŽITELJ (allowlista), a ne zaglavlje tokena.
        if header.get("alg") != ALLOWED_ALGORITHM:
            return None
        expected = b64url_encode(hmac_sha256(parts[0] + "." + parts[1], self._secret))
        # POPRAVAK: usporedba u konstantnom vremenu.
        if not hmac.compare_digest(expected.encode("ascii"), parts[2].encode("ascii")):
            return None
        # POPRAVAK: provjera isteka (exp je obavezan).
        exp = payload.get("exp")
        if not isinstance(exp, int | float) or exp <= datetime.now(UTC).timestamp():
            return None
        return payload
    except (ValueError, UnicodeDecodeError, UnicodeEncodeError, AttributeError):
        return None
```

Tajna dolazi iz `config.py`: `lab12_jwt_secret = os.environ.get("LAB12_JWT_SECRET") or secrets.token_urlsafe(32)`.

</details>

## 7. Provjera popravka

### (a) Testovi

```bash
pytest -m lab12
pytest -m "lab12 and security"
```

U PyCharmu: zelena strelica ▶ pokraj funkcije testa, ili desni klik na `tests/lab12` → *Run 'pytest in
lab12'*. U VS Codeu: panel **Testing** (ikona tikvice/*flask*).

- `test_alg_none_token_is_rejected` – prije **PADA** (alg:none → 200), poslije **PROLAZI** (→ 401).
- `test_token_signed_with_weak_secret_is_rejected` – prije **PADA** (token potpisan `secret123` → 200),
  poslije **PROLAZI** (→ 401, jer je tajna sada jaka i nije u listi).
- `test_expired_token_is_rejected` (koristi `app.state.lab12_jwt.create_token` s prošlim `exp`) – prije
  **PADA** (istekli token → 200), poslije **PROLAZI** (→ 401).
- Funkcionalni testovi (login → `/me` 200, USER na `/admin` → 403, ADMIN na `/admin` → 200) prolaze na obje
  grane.

### (b) Ponovljeni napad

Nakon popravka svi napadi iz koraka 4 vraćaju **401** `{"error":"Neispravan token."}`: `alg:none` se odbija
(algoritam nije na allowlisti), token potpisan `secret123` ne prolazi (poslužiteljska tajna je druga), a
istekli token pada na provjeri `exp`.

### (c) Alati

- **Ruff:** `ruff check vulnshop --select S` na grani `main` prijavljuje samo hardkodiranu tajnu
  (`S105` u `vulnshop/config.py`), a **Bandit** (`bandit -c pyproject.toml -r vulnshop`) ni to. Logičke
  propuste (`alg: none`, izostala provjera `exp`, usporedba potpisa) ne prijavljuje nijedan od njih – dobar
  primjer da statička analiza ne hvata sve, pa ručnu provjeru potpisa treba pregledati i pokriti testovima.
- **jwt_tool** / **jwt.io** za ručnu analizu i krivotvorenje tokena pri eksploataciji.

## 8. Zadatak za samostalni rad

- Napiši dodatni pytest test koji provjerava da token s izmijenjenim payloadom (npr. `role` promijenjen u
  `ADMIN` nakon potpisivanja, bez ponovnog potpisa) biva odbijen sa statusom **401** na `/api/lab12/admin`.

Pitanja za razmišljanje:

1. Zašto je `alg:none` tako opasan i zašto ga provjerene biblioteke danas odbijaju po zadanom?
2. Zašto usporedba potpisa mora biti u konstantnom vremenu i što je *timing side-channel*?
3. Koja je razlika između `exp`, `nbf` i `iat` i zašto ih je korisno provjeravati?
