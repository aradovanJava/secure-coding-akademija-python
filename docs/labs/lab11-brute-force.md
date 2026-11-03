# Lab11 – Authentication Failures (brute force i enumeracija)

## 1. Cilj vježbe

Pokazati kako različiti odgovori za nepostojećeg korisnika i pogrešnu lozinku omogućuju enumeraciju
korisničkih imena, te kako nedostatak ograničenja pokušaja omogućuje brute force. Polaznik uvodi jedinstven
odgovor i zaključavanje računa.

- **OWASP Top 10:2025:** A07 – Authentication Failures
- **CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-204 (Observable Response Discrepancy)

## 2. Gdje je kod

- `vulnshop/lab11/routes.py` → endpoint `POST /api/lab11/login` (funkcija `login`).
- `vulnshop/lab11/data.py` – seed tablice `lab11_users`: `ivana`/`sunshine1` (lozinka je u
  `wordlists/top-100.txt`), `tomislav`/`T0m!slav#2026` (jaka lozinka) te `lockme`/`Lock!Me2026`
  (zaseban korisnik za test zaključavanja).
- Lozinke se provjeravaju preko `vulnshop/common/passwords.py` (Argon2id).
- Testovi: `tests/lab11/test_lab11_security.py` i `tests/lab11/test_lab11_functional.py`.

## 3. Opis ranjivosti

Za nepostojećeg korisnika vraća se **404 „Korisnik ne postoji."**, a za pogrešnu lozinku **401 „Pogrešna
lozinka."**. Razlika u statusu i tijelu otkriva postoji li korisničko ime (enumeracija). Nema ograničenja
broja pokušaja ni zaključavanja računa, pa je brute force rječnikom lozinki neometan.

## 4. Eksploatacija – korak po korak

> Napad se izvodi **profesionalnim alatima** (Burp Suite Community Intruder ili OWASP ZAP Fuzzer) uz
> `wordlists/top-100.txt`. **U ovom repozitoriju nema – i ne smije biti – vlastitih napadačkih skripti.**
> U `http/lab11.http` nalazi se nekoliko ručnih zahtjeva za usporedbu odgovora.
>
> Pokreni aplikaciju s `python -m vulnshop` (poslužitelj na `http://localhost:8000`, Swagger UI na
> `http://localhost:8000/docs`). Na Linuxu/macOS-u umjesto `curl.exe` pišeš `curl`.

1. **Enumeracija:** pošalji login za postojećeg (`ivana`) i nepostojećeg korisnika, oba s krivom lozinkom, i
   usporedi status i tijelo:
   ```bash
   curl.exe -s -X POST http://localhost:8000/api/lab11/login -H "Content-Type: application/json" -d "{\"username\":\"ivana\",\"password\":\"pogresno\"}"
   curl.exe -s -X POST http://localhost:8000/api/lab11/login -H "Content-Type: application/json" -d "{\"username\":\"ne_postojim\",\"password\":\"pogresno\"}"
   ```
   **Očekivano (ranjivo):**
   - `ivana` + kriva → **401** `{"error":"Pogrešna lozinka."}`
   - `ne_postojim` → **404** `{"error":"Korisnik ne postoji."}`

   Razlika u statusu/tijelu = dokaz enumeracije (napadač tako gradi popis valjanih korisničkih imena).
2. **Brute force (Burp Suite Intruder):** uhvati zahtjev za `ivana`, pošalji ga u *Intruder*, način
   **Sniper**, a oznaku (`§…§`) postavi na vrijednost polja `password`. *Payloads* → *Payload type: Simple
   list* → učitaj `wordlists/top-100.txt`. Pokreni napad i sortiraj rezultate po **Status** i **Length**.
   Kako je `sunshine1` u listi, taj pokušaj se izdvaja: **200** `{"status":"prijavljen","username":"ivana"}`,
   dok ostali daju 401/404.
   - **OWASP ZAP:** desni klik na zahtjev → *Fuzz…* → lokacija = vrijednost `password` → *Payloads* → *File* =
     `wordlists/top-100.txt`; u tablici rezultata traži redak s kodom **200**.

## 5. Analiza uzroka

```python
row = db.query_one("SELECT password_hash FROM lab11_users WHERE username = ?", (username,))
# RANJIVO: posebna poruka i status za nepostojećeg korisnika omogućuju enumeraciju.
if row is None:
    return error(404, "Korisnik ne postoji.")
# RANJIVO: nema brojača neuspjelih pokušaja ni zaključavanja računa.
if not verify_password(row["password_hash"], password):
    return error(401, "Pogrešna lozinka.")
```

Dvije su pogreške: (1) odgovor se razlikuje ovisno o tome postoji li korisnik (različit status i poruka), pa
napadač posredno „čita" tablicu korisnika; (2) ne postoji ograničenje broja pokušaja, pa se cijeli rječnik
može isprobati bez posljedica. Dodatno, za nepostojećeg korisnika uopće se ne provjerava lozinka, pa je
vrijeme odgovora kraće i odaje nepostojanje korisnika i kad bi poruke bile iste (*timing*).

## 6. Popravak

- Jedinstven odgovor **401 „Neispravno korisničko ime ili lozinka."** za oba slučaja (nepostojeći korisnik i
  kriva lozinka).
- Provjeri lozinku i za nepostojećeg korisnika (lažni „dummy" hash) radi ujednačenog vremena odgovora.
- Zaključaj račun nakon 5 neuspjelih pokušaja (15 min) → **429**.
- Napomena: brojač je u memoriji i vrijedi **po procesu**; u produkciji ide u dijeljenu pohranu (npr. Redis).
  Dodatno razmotri MFA, CAPTCHA nakon nekoliko neuspjeha, ograničenje po IP adresi (reverse proxy ili
  biblioteka poput *slowapi*) i provjeru lozinki protiv popisa procurjelih lozinki.

<details>
<summary>Referentno rješenje (grana <code>rjesenja</code>)</summary>

```python
GENERIC_ERROR = "Neispravno korisničko ime ili lozinka."
# Lažni hash za nepostojeće korisnike (ujednačeno vrijeme odgovora).
DUMMY_HASH = hash_password("lazna-lozinka-za-ujednaceno-vrijeme")

# ... LoginAttempts: brojač neuspjeha i vrijeme zaključavanja po korisniku (u memoriji) ...

@router.post("/api/lab11/login")
def login(body: LoginRequest, request: Request, db: DbDep):
    username = body.username or ""
    password = body.password or ""
    attempts = get_attempts(request)
    # POPRAVAK: zaključan račun -> 429 (i prije provjere lozinke).
    if attempts.is_locked(username):
        return error(429, "Previše neuspjelih pokušaja. Pokušajte ponovno kasnije.")

    row = db.query_one("SELECT password_hash FROM lab11_users WHERE username = ?", (username,))
    # POPRAVAK: lozinka se provjerava i kad korisnik ne postoji (lažni hash) -> ujednačeno vrijeme.
    valid = verify_password(row["password_hash"] if row else DUMMY_HASH, password)
    if row is None or not valid:
        attempts.record_failure(username)
        # POPRAVAK: isti status i ista poruka za oba slučaja.
        return error(401, GENERIC_ERROR)

    attempts.reset(username)
    return {"status": "prijavljen", "username": username}
```

</details>

## 7. Provjera popravka

### (a) Testovi

```bash
pytest -m lab11
pytest -m "lab11 and security"
```

U PyCharmu: zelena strelica ▶ pokraj funkcije testa, ili desni klik na mapu `tests/lab11` → *Run 'pytest in
lab11'*. U VS Codeu: panel **Testing** (ikona tikvice/*flask*), pa pokreni grupu `lab11`.

- `test_no_user_enumeration` – prije popravka **PADA** (nepostojeći korisnik 404 ≠ kriva lozinka 401, različito
  tijelo), poslije **PROLAZI** (oba daju isti 401 i isto tijelo).
- `test_account_is_locked_after_five_failures` – prije **PADA** (nema zaključavanja, 6. pokušaj vraća 200),
  poslije **PROLAZI** (nakon 5 neuspjeha za `lockme` i točna lozinka → 429).
- Funkcionalni `test_valid_login` (ispravan login → 200) prolazi na obje grane.

### (b) Ponovljeni napad

Nakon popravka oba zahtjeva iz koraka 4.1 daju **401** `{"error":"Neispravno korisničko ime ili lozinka."}`,
pa razlike za enumeraciju nema. Burp/ZAP više ne pronalazi istaknuti 200 jer se nakon 5 neuspjeha račun
zaključava (**429**).

### (c) Alati

- **Burp Suite Community** – Intruder (Sniper, *payload list* = `wordlists/top-100.txt`); usporedba
  *Status*/*Length*.
- **OWASP ZAP** – Fuzzer (*File* payload = `wordlists/top-100.txt`).

## 8. Zadatak za samostalni rad

- Napiši dodatni pytest test koji provjerava da je nakon zaključavanja za `lockme` **svaki** sljedeći
  pokušaj (i s točnom i s netočnom lozinkom) odbijen sa statusom **429**, a ne 401.

Pitanja za razmišljanje:

1. Zašto i vremenska razlika u odgovoru (*timing*) može odati postoji li korisnik, i kako je lažni hash
   ublažava?
2. Koje su mane zaključavanja po korisničkom imenu (napadač može namjerno zaključati tuđi račun – DoS) i kako
   ih ublažiti (npr. zaključavanje po IP-u, eksponencijalno usporavanje, CAPTCHA)?
3. Zašto brojač pokušaja u memoriji nije dovoljan kad aplikacija radi u više procesa ili instanci, i gdje bi
   se takvo stanje trebalo čuvati?
