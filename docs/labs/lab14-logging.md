# Lab14 – Security Logging & Alerting Failures

## 1. Cilj vježbe

Pokazati tri propusta logiranja: lozinka u logu, log injection kroz CR/LF i izostanak sigurnosnih
događaja/alertiranja. Polaznik uvodi sigurno logiranje i detekciju brute-forcea.

- **OWASP Top 10:2025:** A09 – Security Logging & Alerting Failures
- **CWE:** CWE-778 (Insufficient Logging), CWE-117 (Improper Output Neutralization for Logs), CWE-532 (Insertion of Sensitive Information into Log File)

## 2. Gdje je kod

- `vulnshop/lab14/routes.py` → endpoint `POST /api/lab14/login` (funkcija `login`).
- Format zapisa definiran je u `vulnshop/app.py`: `"%(asctime)s %(levelname)s %(name)s - %(message)s"`.
- Testovi: `tests/lab14/test_lab14_security.py` i `tests/lab14/test_lab14_functional.py` – zapise iz loga
  hvataju ugrađenim pytest fixtureom `caplog` (vrati sve `LogRecord`-e nastale tijekom testa, pa se nad njima
  provjerava sadržaj poruka).

## 3. Opis ranjivosti

```python
log.info("Login attempt user=" + username + " password=" + password)
```

- **CWE-532:** lozinka završava u logu u čistom tekstu.
- **CWE-117:** korisničko ime s `\n` ubacuje lažni redak (npr.
  `ana\n2026-11-02 10:00:00,000 INFO vulnshop.lab14 - Login successful user=admin`) – u logu nastaje redak
  koji izgleda kao legitiman zapis.
- **CWE-778:** neuspjela prijava se **ne** bilježi kao sigurnosni događaj, pa nema ni podloge za otkrivanje
  brute-force napada.

## 4. Eksploatacija – korak po korak

> Posljedice se vide u **logu aplikacije** (konzola), **ne** u HTTP odgovoru. Pokreni aplikaciju s
> `python -m vulnshop` i prati ispis u terminalu. Na Linuxu/macOS-u umjesto `curl.exe` pišeš `curl`.

1. **Lozinka u logu:** pošalji prijavu s poznatom lozinkom i pogledaj konzolu:
   ```bash
   curl.exe -s -X POST http://localhost:8000/api/lab14/login -H "Content-Type: application/json" -d "{\"username\":\"ana\",\"password\":\"TajnaLozinka123\"}"
   ```
   **Očekivano (ranjivo):** u logu se pojavi redak
   `... INFO vulnshop.lab14 - Login attempt user=ana password=TajnaLozinka123`.
2. **Log injection (CR/LF):** pošalji korisničko ime koje sadrži `\n` i lažni redak (vidi `http/lab14.http`):
   ```bash
   curl.exe -s -X POST http://localhost:8000/api/lab14/login -H "Content-Type: application/json" -d "{\"username\":\"ana\n2026-11-02 10:00:00,000 INFO vulnshop.lab14 - Login successful user=admin\",\"password\":\"x\"}"
   ```
   **Očekivano (ranjivo):** jedan zahtjev u logu proizvede **dva** retka; drugi počinje krivotvorenim tekstom
   `2026-11-02 10:00:00,000 INFO vulnshop.lab14 - Login successful user=admin` i izgleda kao da se admin
   uspješno prijavio.
3. **Nedostatak događaja:** višestruke neuspjele prijave ne ostavljaju nikakav `SECURITY_EVENT` /
   `SECURITY_ALERT`, pa SIEM nema što detektirati.

## 5. Analiza uzroka

```python
@router.post("/api/lab14/login")
def login(body: LoginRequest, db: DbDep):
    username = body.username or ""
    password = body.password or ""
    # RANJIVO: lozinka u logu + korisničko ime bez neutralizacije CR/LF.
    log.info("Login attempt user=" + username + " password=" + password)
    row = db.query_one("SELECT password FROM users WHERE username = ?", (username,))
    if row is None or not verify_password(row["password"], password):
        # RANJIVO: neuspjeh se ne bilježi kao sigurnosni događaj.
        return error(401, "Neispravni podaci.")
    log.info("Login successful user=" + username)
    return {"status": "prijavljen", "username": username}
```

Neprovjeren unos (uključujući tajnu) spaja se u poruku loga bez neutralizacije kontrolnih znakova i bez
posebnih sigurnosnih zapisa. Spajanje stringova (`+`) umjesto parametara dodatno olakšava log injection.

## 6. Popravak

- **Nikad** ne logiraj tajne (lozinke, tokene).
- Neutraliziraj CR/LF i ostale kontrolne znakove (`sanitize()` ih zamjenjuje znakom `_`).
- Bilježi sigurnosne događaje: `SECURITY_EVENT LOGIN_FAILED user=... ip=...` (WARNING) i `LOGIN_SUCCESS`
  (INFO), s korisničkim imenom i IP adresom.
- Nakon 5 neuspjeha za istog korisnika unutar 5 minuta: `SECURITY_ALERT BRUTE_FORCE_SUSPECTED ...` (ERROR).
- Koristi *lazy* (`%`-stil) argumente logiranja (`log.warning("... user=%s", user)`) – poruka se formatira
  tek ako se stvarno zapisuje, a argumenti ostaju zasebni.
- Napomena: u praksi strukturirano (JSON) logiranje (*structlog*, *python-json-logger*), centralizacija u
  SIEM, korelacijski ID zahtjeva i zaštita integriteta samih logova.

<details>
<summary>Referentno rješenje (grana <code>rjesenja</code>)</summary>

```python
ALERT_THRESHOLD = 5
ALERT_WINDOW_SECONDS = 5 * 60
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def sanitize(value: str) -> str:
    """POPRAVAK: neutralizacija CR/LF i ostalih kontrolnih znakova (CWE-117)."""
    return _CONTROL_CHARS.sub("_", value)[:100]

# ... FailureTracker: klizni prozor vremena neuspjeha po korisniku ...

@router.post("/api/lab14/login")
def login(body: LoginRequest, request: Request, db: DbDep):
    username = body.username or ""
    password = body.password or ""
    safe_user = sanitize(username)
    client_ip = request.client.host if request.client else "-"
    # POPRAVAK: lozinka se ne zapisuje; korisničko ime je neutralizirano.
    row = db.query_one("SELECT password FROM users WHERE username = ?", (username,))
    if row is None or not verify_password(row["password"], password):
        # POPRAVAK: neuspjela prijava je sigurnosni događaj (lazy %-argumenti).
        log.warning("SECURITY_EVENT LOGIN_FAILED user=%s ip=%s", safe_user, client_ip)
        if _tracker.add(username) >= ALERT_THRESHOLD:
            log.error("SECURITY_ALERT BRUTE_FORCE_SUSPECTED user=%s ip=%s", safe_user, client_ip)
        return error(401, "Neispravni podaci.")
    log.info("SECURITY_EVENT LOGIN_SUCCESS user=%s ip=%s", safe_user, client_ip)
    return {"status": "prijavljen", "username": username}
```

</details>

## 7. Provjera popravka

### (a) Testovi

```bash
pytest -m lab14
pytest -m "lab14 and security"
```

U PyCharmu: zelena strelica ▶ pokraj funkcije testa, ili desni klik na `tests/lab14` → *Run 'pytest in
lab14'*. U VS Codeu: panel **Testing** (ikona tikvice/*flask*). Testovi koriste ugrađeni `caplog` fixture:
nakon poziva endpointa provjeravaju poruke zabilježene u logeru `vulnshop.lab14`.

- `test_password_is_not_logged` – prije **PADA** (lozinka `Ana123!` je u logu), poslije **PROLAZI**.
- `test_no_log_injection` – prije **PADA** (CR/LF stvara krivotvoreni redak), poslije **PROLAZI** (CR/LF →
  `_`).
- `test_failed_login_creates_security_event` – prije **PADA** (nema `SECURITY_EVENT LOGIN_FAILED`), poslije
  **PROLAZI**.
- `test_five_failures_raise_alert` – prije **PADA** (nema `SECURITY_ALERT`), poslije **PROLAZI** (nakon 5
  neuspjeha za `marko`).
- Funkcionalni `test_valid_login` (ispravan login → 200) prolazi na obje grane.

### (b) Ponovljeni napad

Nakon popravka u logu nema `password=...`, a napad iz koraka 4.2 daje
`... WARNING vulnshop.lab14 - SECURITY_EVENT LOGIN_FAILED user=ana_...FORGED... ip=...` u **jednom** retku
(CR/LF su zamijenjeni s `_`), pa krivotvorenog retka nema. Nakon 5 neuspjeha pojavi se
`... ERROR vulnshop.lab14 - SECURITY_ALERT BRUTE_FORCE_SUSPECTED user=marko ip=...`.

### (c) Alati

- **ELK / Graylog / SIEM** za centralizaciju i alertiranje; za vježbu je dovoljan ispis u konzolu koji
  testovi hvataju `caplog`-om.

## 8. Zadatak za samostalni rad

- Napiši dodatni pytest test koji provjerava da zapis `SECURITY_EVENT LOGIN_SUCCESS` nastaje pri uspješnoj
  prijavi i da sadrži korisničko ime i IP adresu, ali **ne** sadrži lozinku.

Pitanja za razmišljanje:

1. Koje podatke nikad ne logirati (lozinke, tokeni, OIB, brojevi kartica) i zašto?
2. Zašto je log injection opasan za integritet istrage nakon incidenta?
3. Što čini „dovoljno" logiranja za detekciju napada bez pretjeranog šuma, i kakvu ulogu ima klizni prozor
   kod otkrivanja brute-forcea?
