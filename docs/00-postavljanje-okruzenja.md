# 00 – Postavljanje okruženja (Python / FastAPI)

Ovaj dokument vodi te kroz postavljanje razvojnog okruženja za Python verziju VulnShop Akademije.
Cilj je da u 15-ak minuta imaš pokrenutu aplikaciju i da možeš pokretati testove po vježbama.

> Paralelne Java i .NET verzije imaju vlastite upute u svojim repozitorijima. Vježbe, URL-ovi i seed podaci
> su identični; razlikuje se samo port (Python: **8000**, Java: 8080, .NET: 5080).

## 1. Preduvjeti

| Alat | Verzija | Napomena |
|---|---|---|
| Python | **3.12 ili noviji** | provjereno na 3.12, 3.13 i 3.14 |
| pip | uz Python | instalira ovisnosti iz `requirements*.txt` |
| Git | bilo koja novija | za kloniranje i prebacivanje grana |
| IDE | PyCharm / VS Code | po izboru |

### Instalacija Pythona

- **Windows:** preuzmi instalacijski program s <https://www.python.org/downloads/> i u prvom koraku
  označi *„Add python.exe to PATH"*. Alternativa: `winget install Python.Python.3.13` ili
  *Python Install Manager* iz Microsoft Storea. Na Windowsu je dostupan i pokretač `py` (npr. `py -3.13`).
- **macOS:** instalacijski program s python.org ili `brew install python@3.13`.
- **Linux (Debian/Ubuntu):** `sudo apt install python3 python3-venv python3-pip` (ako je verzija starija
  od 3.12, koristi `deadsnakes` PPA, `pyenv` ili `uv python install 3.13`).
- Provjera:
  ```bash
  python --version      # na Linuxu/macOS-u po potrebi python3 --version; mora biti 3.12+
  ```

## 2. Kloniranje repozitorija

```bash
git clone https://github.com/aradovanJava/secure-coding-akademija-python.git
cd secure-coding-akademija-python
```

## 3. Virtualno okruženje i ovisnosti (naredbeni redak)

Ovisnosti se uvijek instaliraju u **virtualno okruženje** (`.venv` u korijenu repozitorija), a ne u
sustavski Python.

**Windows (PowerShell):**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
```

**Linux / macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
```

Aktivno okruženje prepoznaješ po prefiksu `(.venv)` u naredbenom retku. `requirements-dev.txt` uključuje
`requirements.txt` (aplikacija) i alate: pytest, pytest-cov, Bandit, Ruff, pip-audit i CycloneDX.

> **Brža alternativa – uv:** ako koristiš [uv](https://docs.astral.sh/uv/), isto postižeš s
> `uv venv` i `uv pip install -r requirements-dev.txt`.

## 4. PyCharm

1. Na početnom zaslonu odaberi **Clone Repository** (ili **File → Project from Version Control…**),
   zalijepi URL repozitorija i klikni **Clone**. Već klonirani repozitorij otvaraš s **File → Open…**.
2. **Interpreter:** PyCharm obično sam ponudi stvaranje virtualnog okruženja. Ako ne, otvori
   **Settings → Project: secure-coding-akademija-python → Python Interpreter → Add Interpreter →
   Add Local Interpreter… → Virtualenv Environment** (*New*, lokacija `.venv`, osnovni interpreter 3.12+).
3. **Ovisnosti:** otvori `requirements-dev.txt` i klikni ponuđeno *Install requirements*, ili u ugrađenom
   terminalu (**View → Tool Windows → Terminal**, okruženje je već aktivno) pokreni
   `pip install -r requirements-dev.txt`.
4. **Pokretanje aplikacije:** desni klik na `run.py` → **Run 'run'** (ili **Debug 'run'**). Alternativa:
   **Run → Edit Configurations… → + → Python**, umjesto *script* odaberi **module** i upiši `vulnshop`.
   Aplikacija radi na `http://localhost:8000`, a Swagger UI na `http://localhost:8000/docs`.
5. **Testovi:** u **Settings → Tools → Python Integrated Tools** postavi *Default test runner* na
   **pytest**. Zatim:
   - zelena strelica ▶ pokraj testne funkcije pokreće jedan test,
   - desni klik na mapu `tests/lab07` → **Run 'pytest in lab07'** pokreće cijelu vježbu,
   - za skupine po oznakama: **Run → Edit Configurations… → + → pytest**, *Target*: `tests`, a u
     *Additional Arguments* upiši npr. `-m security` ili `-m "lab07 and security"`.
6. **`.http` datoteke:** ako tvoje izdanje PyCharma ima ugrađeni *HTTP Client*, otvori datoteku iz `http/`
   i klikni zelenu strelicu uz zahtjev (varijablu `@token` postavi ručno iz odgovora na `login`). Inače
   koristi Swagger UI (`/docs`), `curl` ili VS Code s proširenjem REST Client.

## 5. VS Code

1. Instaliraj proširenja (VS Code ih nudi sam jer su navedena u `.vscode/extensions.json`):
   - **Python** (Microsoft) – uključuje Pylance i Python Debugger
   - **Ruff** (Astral) – linter sa sigurnosnim pravilima
   - **REST Client** (Huachao Mao) – za `.http` datoteke
   - po želji **SonarQube for IDE**
2. **File → Open Folder…** → odaberi direktorij repozitorija (ili *Git: Clone* iz Command Palettea,
   `Ctrl+Shift+P`).
3. **Interpreter:** Command Palette → **Python: Create Environment… → Venv** → odaberi Python 3.12+ i
   označi `requirements-dev.txt` da se ovisnosti odmah instaliraju. Ako `.venv` već postoji:
   **Python: Select Interpreter** → `.venv`.
4. **Pokretanje aplikacije:** **Run and Debug** (`Ctrl+Shift+D`) → konfiguracija
   **„VulnShop (uvicorn, port 8000)"** → ▶ (ili `F5`). Konfiguracije su u `.vscode/launch.json`.
5. **Testovi:** **Testing** panel (ikona epruvete) automatski pronalazi pytest testove
   (`.vscode/settings.json`). Za pokretanje po oznakama koristi terminal (odjeljak 6).
6. **`.http` datoteke:** otvori datoteku iz `http/` i klikni *Send Request* iznad zahtjeva.

## 6. Naredbeni redak – pokretanje i testovi

```bash
# Pokretanje aplikacije (port 8000; Swagger UI: http://localhost:8000/docs)
python -m vulnshop
# ili s automatskim ponovnim učitavanjem nakon izmjene koda:
uvicorn vulnshop.main:app --reload --port 8000

# Testovi po skupinama / vježbama (pytest oznake)
pytest -m functional
pytest -m security
pytest -m lab07
pytest -m "lab07 and security" -v

# Pokrivenost koda testovima (izvještaj u terminalu i HTML u htmlcov/)
pytest --cov=vulnshop --cov-report=term-missing --cov-report=html
```

### Prebacivanje na granu s rješenjima

```bash
git switch rjesenja
pip install -r requirements-dev.txt     # grane imaju različitu verziju jinja2 (Lab05)
pytest                                  # svi testovi prolaze
git switch main
pip install -r requirements-dev.txt
```

### PowerShell: curl

U PowerShellu je `curl` alias za `Invoke-WebRequest` i ima drukčiju sintaksu. Koristi **`curl.exe`**
(pravi curl) ili `Invoke-RestMethod`:

```powershell
# Pravi curl (preporuka za primjere iz uputa):
curl.exe -s -X POST http://localhost:8000/api/auth/login `
  -H "Content-Type: application/json" `
  -d '{\"username\":\"ana\",\"password\":\"Ana123!\"}'

# Ili Invoke-RestMethod:
Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/auth/login `
  -ContentType "application/json" `
  -Body '{"username":"ana","password":"Ana123!"}'
```

### Swagger UI

FastAPI automatski generira interaktivnu dokumentaciju na `http://localhost:8000/docs`. Pozovi
`POST /api/auth/login`, kopiraj `token` iz odgovora, klikni **Authorize** (gore desno) i zalijepi token –
svi daljnji zahtjevi iz sučelja šalju ga u zaglavlju `Authorization`.

## 7. Rješavanje čestih problema

| Problem | Rješenje |
|---|---|
| `Address already in use` / port 8000 zauzet | Zatvori proces na 8000 ili pokreni na drugom portu: PowerShell `$env:PORT=8001; python -m vulnshop`, Linux/macOS `PORT=8001 python -m vulnshop`. Na Windowsu: `netstat -ano \| findstr :8000` pa `taskkill /PID <pid> /F`. |
| `.\.venv\Scripts\Activate.ps1 cannot be loaded … running scripts is disabled` | Jednokratno: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, ili aktiviraj iz `cmd.exe` s `.venv\Scripts\activate.bat`. |
| `ModuleNotFoundError: No module named 'vulnshop'` | Pokreći naredbe iz **korijena repozitorija** (gdje je `pyproject.toml`) i s aktivnim `.venv`. |
| `ModuleNotFoundError: No module named 'fastapi'` (ili sličan) | Ovisnosti nisu instalirane u odabrani interpreter: aktiviraj `.venv` i `pip install -r requirements-dev.txt`; u IDE-u provjeri da je odabran interpreter iz `.venv`. |
| Pogrešna verzija Pythona (sintaksne greške pri pokretanju) | Treba 3.12+. Na Windowsu stvori okruženje s `py -3.13 -m venv .venv`. |
| pip ne može preuzeti pakete (proxy) | `pip install --proxy http://korisnik:lozinka@proxy:port -r requirements-dev.txt` ili postavi `HTTPS_PROXY`. |
| `.http` zahtjev vraća 401 | Nisi postavio `@token`. Prvo pozovi `login`, kopiraj `token` iz odgovora u varijablu `@token`. |
| Lab05 test verzije pada i na grani `rjesenja` | Nakon `git switch` nisi ponovno instalirao ovisnosti: `pip install -r requirements-dev.txt`. |
| Lab09: izlaz naredbe `ping` je „čudnih" znakova (Windows) | Konzola koristi kodnu stranicu 852/1250; to ne utječe na vježbu (bitno je pojavljuje li se `PWNED_LAB09`). |
