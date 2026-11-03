# 01 – Profesionalni alati (Tjedan 1)

Ovdje su alati koje koristimo u Tjednu 1, s **konkretnim naredbama nad VulnShop Akademijom (Python)**.
Gdje alat nije dio CI-a, to je jasno naznačeno (pokreće se lokalno).

> Aplikacija radi na `http://localhost:8000`. Pokreni je (`python -m vulnshop`) prije dinamičkih alata.
> Naredbe za Python alate pokreći iz korijena repozitorija, s aktivnim virtualnim okruženjem (`.venv`).

## 1. OWASP ZAP (Zed Attack Proxy) – DAST

Besplatan alat za dinamičko testiranje pokrenute aplikacije.

- **Uvoz API-ja (preporuka za FastAPI):** *Import → Import an OpenAPI Definition from a URL* →
  `http://localhost:8000/openapi.json`. ZAP tako odmah upozna sve endpointe i parametre.
- **Automated Scan:** *Quick Start → Automated Scan*, URL `http://localhost:8000`, *Attack*.
  Očekuj nalaze za lab04 (nedostatak sigurnosnih zaglavlja, CORS), lab08 (XSS), lab07 (SQL injection).
- **Manual Explore:** otvori preglednik kroz ZAP proxy i ručno prođi stranice iz lab08.
- **Fuzzer (lab11):** u *History* odaberi `POST /api/lab11/login`, desni klik → *Attack → Fuzz*; označi
  vrijednost `password`, dodaj *File* payload = `wordlists/top-100.txt`. Za `ivana` ćeš dobiti 200 na
  `sunshine1`.

## 2. Burp Suite Community

- **Proxy:** uhvati promet preglednika ili Swagger UI-ja (`/docs`).
- **Repeater:** ručno mijenjaj zahtjeve (idealno za lab01 IDOR – mijenjaj `id`, lab07 SQLi – mijenjaj `q`).
- **Intruder (lab11):** Sniper napad na `password`, payload set iz `wordlists/top-100.txt`.

## 3. SonarQube for IDE (SonarLint)

Instaliraj u PyCharm ili VS Code. Prikazuje „Security Hotspots" dok tipkaš — primijeti upozorenja za
SQL sastavljen iz stringova (lab07), `pickle.loads` (lab13), MD5 i ECB (lab06), `shell=True` (lab09).

## 4. Bandit – SAST za Python

Bandit je standardni alat za statičku sigurnosnu analizu Python koda (dio PyCQA). Postavke su u
`pyproject.toml` (`[tool.bandit]`).

```bash
bandit -c pyproject.toml -r vulnshop                 # svi nalazi
bandit -c pyproject.toml -r vulnshop -lll            # samo visoka ozbiljnost
bandit -c pyproject.toml -r vulnshop -f html -o bandit.html
```

Na grani `main` prijavljuje npr. `B608` (SQL iz stringova, lab07), `B602` (`shell=True`, lab09),
`B301`/`B403` (`pickle`, lab13), `B324` (MD5, lab06), `B305` (ECB, lab06) i `B310` (`urlopen`, lab03).
Svjesno prihvaćen nalaz označava se komentarom `# nosec B603` **uz obrazloženje** (vidi lab09 na grani
`rjesenja`).

## 5. Ruff – linter sa sigurnosnim pravilima

Ruff je vrlo brz linter; pravila `S` su Banditova pravila (flake8-bandit), pa nalaze vidiš odmah u IDE-u.

```bash
ruff check vulnshop --select S          # samo sigurnosna pravila
ruff check .                            # sva pravila iz pyproject.toml
```

Primijeti da `S608` označava i poruku greške u lab15 – to nije SQL injection (lažno pozitivan nalaz), ali
upućuje na stvaran problem: SQL i nazivi tablica završavaju u odgovoru korisniku. Svaki nalaz alata treba
**analizirati**, a ne slijepo ispravljati ili ignorirati.

## 6. Semgrep

```bash
pip install semgrep            # ili: pipx install semgrep / Docker image semgrep/semgrep
semgrep scan --config p/python --config p/owasp-top-ten .
```

Prijavljuje npr. SQL injection (lab07), command injection (lab09), nesigurnu deserijalizaciju (lab13) i
SSRF obrasce (lab03). Pokreće se **lokalno** (nije u ovom CI-u). Semgrep se namjerno ne nalazi u
`requirements-dev.txt` jer ima mnogo vlastitih ovisnosti.

## 7. pip-audit – SCA (lab05)

```bash
pip-audit -r requirements.txt           # analizira datoteku s ovisnostima
pip-audit                               # analizira pakete instalirane u aktivnom okruženju
```

Na grani `main` pronalazi ranjivu `jinja2 3.1.4` (identifikatori PYSEC/GHSA i CVE-2024-56326,
CVE-2024-56201, CVE-2025-27516) i predlaže verziju s ispravkom. Na grani `rjesenja`: *No known
vulnerabilities found*.

## 8. OSV-Scanner

```bash
osv-scanner scan source -r .
```

Čita `requirements.txt` i javlja ranjive verzije (jinja2 3.1.4). Instalacija: <https://google.github.io/osv-scanner/>.

## 9. Trivy

```bash
trivy fs .
```

Skenira ovisnosti iz `requirements.txt` (i, ako gradiš image, kontejner). Brz pregled poznatih ranjivosti.

## 10. CycloneDX (SBOM)

```bash
cyclonedx-py requirements requirements.txt -o sbom.cdx.json    # iz datoteke s ovisnostima
cyclonedx-py environment -o sbom-env.cdx.json                  # iz instaliranog okruženja (s tranzitivnim)
```

SBOM (*Software Bill of Materials*) je popis svih komponenti; kad se objavi novi CVE, iz SBOM-a se odmah
vidi koji su sustavi pogođeni.

## 11. GitHub Dependabot

U repozitoriju na GitHubu uključi *Dependency graph* i *Dependabot alerts*. Automatski će prijaviti ranjivu
`jinja2` 3.1.4 iz `requirements.txt` i predložiti nadogradnju (grana `rjesenja` je već na 3.1.6).

---

## Što je u CI-u, a što lokalno

| Alat | U CI-u (GitHub Actions)? | Napomena |
|---|---|---|
| pytest – funkcionalni i sigurnosni testovi | **Da** (posao „Testovi", Python 3.12 i 3.14) | sažetak po vježbi u anotacijama |
| Bandit, Ruff (pravila S), pip-audit, CycloneDX SBOM | **Da, informativno** (posao „Sigurnosni alati") | nalazi ne ruše build; SBOM se sprema kao artefakt |
| Semgrep / OSV-Scanner / Trivy / ZAP / Burp | Ne (lokalno) | trebaju vlastitu instalaciju |
| Dependabot | Da (GitHub platforma) | izvan workflowa |

Preporuka: u stvarnom projektu SAST i SCA neka budu **sigurnosna vrata** u CI-u (zaseban posao s pragom
ozbiljnosti koji ruši build), a svjesno prihvaćeni nalazi evidentiraju se s obrazloženjem.
