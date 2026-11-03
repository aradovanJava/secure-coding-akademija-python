# Lab09 – OS command injection

## 1. Cilj vježbe

Pokazati kako umetanje korisničkog unosa u naredbu ljuske (*shell*) omogućuje izvršavanje proizvoljnih
naredbi na poslužitelju, te to ispraviti strogom validacijom i izbjegavanjem ljuske.

- **OWASP Top 10:2025:** A05 – Injection
- **CWE:** CWE-78 (*OS Command Injection*)

## 2. Gdje je kod

- `vulnshop/lab09/routes.py` — funkcija `ping(host)` → `GET /api/lab09/ping?host=`
- Lab09 nema vlastitih tablica (`vulnshop/lab09/data.py` samo deklarira `init`).
- Testovi: `tests/lab09/test_lab09_security.py`, `tests/lab09/test_lab09_functional.py`.

## 3. Opis ranjivosti

Endpoint sastavlja naredbu `ping -c 1 <host>` (na Windowsu `-n`) i pokreće je sa `shell=True`. Ljuska (`/bin/sh`, `cmd.exe`) ne izvršava samo jedan program — ona **interpretira** cijeli redak: `&`, `&&`, `|`, `;`, `` ` ``, `$( )`, preusmjeravanja `>`… Kako `host` dolazi izravno od korisnika, napadač metaznakovima nadovezuje vlastite naredbe koje se izvršavaju s ovlastima aplikacije. Ovo je jedna od najtežih posljedica — izravno izvršavanje koda (RCE). Isti obrazac proslavili su *Shellshock* (2014.) i brojne „ping/traceroute“ dijagnostičke stranice mrežnih uređaja.

## 4. Eksploatacija – korak po korak

Pokrenite aplikaciju s `python -m vulnshop` (host `http://localhost:8000`). Zahtjevi su u `http/lab09.http` (koristite URL-enkodirane oblike iz te datoteke); isto možete izvesti i kroz **Swagger UI** na `http://localhost:8000/docs`. Na Linuxu/macOS-u umjesto `curl.exe` pišete `curl`.

1. **Legitimni poziv:** `GET /api/lab09/ping?host=127.0.0.1` → `200` s izlazom naredbe `ping`.
2. **Nadovezivanje (radi u `cmd` i u `sh`):** `host = 127.0.0.1 & whoami`

   ```
   GET /api/lab09/ping?host=127.0.0.1%20%26%20whoami
   ```

   **Očekivano (ranjivo):** u polju `output` je, uz izlaz pinga, i ime korisničkog računa pod kojim radi aplikacija (npr. `ana` ili `racunalo\ana`) — dokaz izvršavanja proizvoljne naredbe.
3. **Bezopasni marker (isti payload koristi test):** `host = 127.0.0.1 & echo PWNED_LAB09`

   ```
   GET /api/lab09/ping?host=127.0.0.1%20%26%20echo%20PWNED_LAB09
   ```

   **Očekivano (ranjivo):** u izlazu se pojavi `PWNED_LAB09`.
4. **Linux/macOS:** `host = 127.0.0.1; cat /etc/passwd` → sadržaj datoteke sustava.
5. **Windows:** `host = 127.0.0.1 & type C:\Windows\win.ini` → sadržaj datoteke sustava.

> Ako na sustavu nema naredbe `ping` (npr. neki CI *runneri*), razlika je samo u tekstu izlaza — umjesto rezultata pinga vidjet ćete poruku o nedostatku naredbe, ali **ubačena naredba (`whoami`, `echo`, `cat`) i dalje se izvrši**, jer je metaznak ljuske razdvoji od `ping`. To i jest poanta napada.

## 5. Analiza uzroka

```python
count_flag = "-n" if platform.system() == "Windows" else "-c"
command = f"ping {count_flag} 1 {host}"
# RANJIVO: shell=True + korisnički unos u naredbenom retku (cmd.exe ili /bin/sh).
result = subprocess.run(command, shell=True, capture_output=True, text=True, errors="replace", timeout=10)
```

Pokretanjem kroz ljusku (`shell=True`) cijeli se string interpretira, pa `&`/`;`/`|` razdvajaju naredbe.

## 6. Popravak

- **Stroga validacija (allowlista):** host mora biti valjana IP adresa (`ipaddress`) ili ime hosta po regexu `^(?!-)[A-Za-z0-9.-]{1,253}$`. Pravilo „ne smije počinjati crticom“ sprječava da host postane opcija programa (*argument injection*, CWE-88). Allowlista (što je dopušteno) pouzdanija je od blockliste (koje znakove zabraniti).
- **Bez ljuske:** `subprocess.run([...], shell=False)` s **listom argumenata** — host je jedan argument, pa `&`, `;`, `|` nemaju posebno značenje. Program nađite kroz `shutil.which("ping")`.
- **Još bolje:** ne pokretati vanjski program kad postoji biblioteka (TCP provjera dostupnosti preko modula `socket`, ili paket `icmplib`). Aplikaciju pokrećite s najmanjim ovlastima, u kontejneru bez nepotrebnih alata.

### O statičkim nalazima (odgovorna trijaža)

Bandit/Ruff prijavljuju `B603`/`S603` za **svaki** `subprocess` poziv s promjenjivim argumentima — i nakon popravka, jer alat ne može dokazati da je `host` validiran. Ispravljeni kod zato svjesno prihvaća taj nalaz i dokumentira ga: `# noqa: S603  # nosec B603` uz komentar koji objašnjava zašto je poziv siguran (host je validiran, nema ljuske). Tako se uči odgovorno rukovanje nalazima — ne gasiti ih paušalno, nego svaki pojedinačno opravdati.

<details>
<summary>Referentno rješenje (grana <code>rjesenja</code>)</summary>

```python
HOSTNAME_PATTERN = re.compile(r"^(?!-)[A-Za-z0-9.-]{1,253}$")

def is_valid_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return "%" not in host  # bez IPv6 "zone" sufiksa (npr. fe80::1%eth0) - on dopušta proizvoljan tekst
    except ValueError:
        return bool(HOSTNAME_PATTERN.fullmatch(host))

@router.get("/api/lab09/ping")
def ping(host: str):
    # POPRAVAK 1: stroga validacija (allowlista dopuštenih znakova).
    if not is_valid_host(host):
        return error(400, "Neispravan host.")
    ping_executable = shutil.which("ping")
    if ping_executable is None:
        return {"host": host, "output": "Naredba ping nije dostupna na ovom sustavu."}
    count_flag = "-n" if platform.system() == "Windows" else "-c"
    # POPRAVAK 2: bez ljuske – lista argumenata, host je samo jedan argument.
    # Host je validiran i nema ljuske, pa je nalaz alata S603/B603 ovdje svjesno prihvaćen.
    result = subprocess.run(  # noqa: S603  # nosec B603
        [ping_executable, count_flag, "1", host],
        shell=False, capture_output=True, text=True, errors="replace", timeout=10,
    )
    return {"host": host, "output": result.stdout + result.stderr}
```

</details>

## 7. Provjera popravka

### a) Testovi

```
pytest -m lab09
pytest -m "lab09 and security"
```

IDE: u PyCharmu kliknite zeleni ▶ pokraj testne funkcije (ili desni klik na `tests/lab09` → *Run 'pytest in lab09'*); u VS Codeu otvorite panel *Testing* (ikona tikvice) i pokrenite `tests/lab09`.

- **Prije popravka** padaju: `test_ampersand_chaining_is_blocked` (`127.0.0.1 & echo PWNED_LAB09` izvrši `echo`) i `test_semicolon_chaining_is_blocked` (`127.0.0.1;id`).
- **Poslije popravka** oba prolaze: obje vrijednosti vraćaju `400` i izlaz ne sadrži `PWNED_LAB09`. Funkcionalni (`test_valid_host_returns_200` — `host=127.0.0.1` → `200`, neovisno o tome je li ping stvarno uspio) prolazi na obje grane.

### b) Ponovljeni napad

Nakon popravka zahtjevi iz koraka 2–5 vraćaju `400 {"error":"Neispravan host."}`, a `host=127.0.0.1` i `host=localhost` i dalje rade (vraćaju izlaz pinga ili poruku da ping nije dostupan).

### c) Ponovno skeniranje

```
bandit -c pyproject.toml -r vulnshop
ruff check vulnshop --select S
semgrep scan --config p/python
```

Na grani `main` Bandit (`B602`) i Ruff (`S602`) prijavljuju `subprocess` sa `shell=True`. Nakon popravka tog (najtežeg) nalaza nema; ostaje `B603`/`S603`, ali svjesno prihvaćen i dokumentiran kao gore. Dinamički: **OWASP ZAP** *Active Scan* nad `host` prijavljuje *Remote OS Command Injection*; Burp Intruder s listom separatora (`&`, `&&`, `|`, `;`, `%0a`).

## 8. Zadatak za samostalni rad

- Dodajte endpoint `GET /api/lab09/lookup?host=` koji IP adrese hosta dobiva bibliotekom (`socket.getaddrinfo`), **bez pokretanja vanjskog programa**, i **napišite dodatni pytest test** koji dokazuje da `example.com;id` i `-oProxyCommand=x` vraćaju `400`, a valjano ime `200`.

**Pitanja za razmišljanje:**
1. Zašto validacija (allowlista) i izbjegavanje ljuske trebaju ići zajedno, a ne jedno ili drugo?
2. Koja je razlika između *command injection* i *argument injection*? Štiti li lista argumenata (`shell=False`) od obje?
3. Kako bi pokretanje aplikacije s najmanjim ovlastima (ili u kontejneru) ograničilo štetu ovog napada?
