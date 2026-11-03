# Lab05 – Software Supply Chain Failures (ranjiva ovisnost)

## 1. Cilj vježbe

Pokazati rizik ranjive ovisnosti (*third-party library*) na primjeru `jinja2 3.1.4` i njezinih poznatih
ranjivosti bijega iz sandboxa, te kako ih otkriti alatima i ispraviti nadogradnjom + ispravnom uporabom.
Analogno je Text4Shellu iz Java verzije vježbe.

- **OWASP Top 10:2025:** A03 – Software Supply Chain Failures
- **CWE:** CWE-1104 (*Use of Unmaintained Third Party Components*), CWE-1395 (*Dependency on Vulnerable Component*)

## 2. Gdje je kod

- `vulnshop/lab05/routes.py` – funkcija `greeting(body)` → `POST /api/lab05/greeting`.
- Verzija ovisnosti: `requirements.txt` → `jinja2==3.1.4` na `main`, `jinja2==3.1.6` na `rjesenja`.
- `vulnshop/lab05/data.py` – vježba nema vlastitih tablica.
- Testovi: `tests/lab05/test_lab05_security.py` i `tests/lab05/test_lab05_functional.py`.

## 3. Opis ranjivosti

Ranjivost je na dvije razine:

1. **Ovisnost:** `jinja2 3.1.4` ima poznate ranjivosti sandboxa (CVE-2024-56326, CVE-2024-56201,
   CVE-2025-27516), ispravljene u 3.1.5 / 3.1.6. Napadač koji smije pisati predložak može u ranjivoj verziji
   **pobjeći iz `SandboxedEnvironment`** i izvršiti proizvoljan Python kod (RCE).
2. **Uporaba:** korisnički unos postaje dio **predloška** (*server-side template injection*, SSTI).
   Programer se oslonio na `SandboxedEnvironment` — ali sandbox ranjive verzije ne štiti, a i da štiti, i dalje
   bi se izvršavali izrazi iz unosa.

Kontroler poziva `_env.from_string("Pozdrav, " + name + "!")`, pa Jinja2 u imenu izvršava `{{ ... }}` izraze.

## 4. Eksploatacija – korak po korak

Pokrenite aplikaciju s `python -m vulnshop` (host `http://localhost:8000`). Gotovi zahtjevi su u
`http/lab05.http`; iste pozive možete izvesti i kroz **Swagger UI** na `http://localhost:8000/docs`. Na
Linuxu/macOS-u umjesto `curl.exe` pišete `curl`. Endpoint ne traži prijavu.

1. Običan pozdrav (radi uvijek):
   ```
   curl.exe -s -X POST http://localhost:8000/api/lab05/greeting -H "Content-Type: application/json" -d "{\"name\":\"Ana\"}"
   ```
   → `{"greeting":"Pozdrav, Ana!"}`.
2. **SSTI – izraz se izvršava na poslužitelju:**
   ```
   curl.exe -s -X POST http://localhost:8000/api/lab05/greeting -H "Content-Type: application/json" -d "{\"name\":\"{{ 7*7 }}\"}"
   ```
   **Očekivano (ranjivo):** `{"greeting":"Pozdrav, 49!"}` umjesto doslovnog `{{ 7*7 }}`.
3. **Izvršavanje funkcija i filtara:** `name` = `{{ range(5)|list }} {{ 'abc'|upper }}`.
   **Očekivano (ranjivo):** `{"greeting":"Pozdrav, [0, 1, 2, 3, 4] ABC!"}`.
4. **Konceptualno (bez gotovog *exploita*):** sandbox blokira izravan pristup internim atributima — `{{
   ''.__class__ }}` vraća prazno, a `{{ ''.__class__.__mro__ }}` baca `SecurityError`. Međutim, **ranjiva
   verzija 3.1.4 ima poznate načine bijega iz sandboxa** (CVE-2024-56326, CVE-2025-27516): dovoljno smislen
   payload u ranjivoj verziji vodi do izvršavanja proizvoljnog koda. Gotov *exploit* namjerno ne pišemo —
   poanta vježbe je **nadograditi i ne interpolirati**, a ne usavršiti bijeg.

## 5. Analiza uzroka

```python
_env = SandboxedEnvironment()

@router.post("/api/lab05/greeting")
def greeting(body: GreetingRequest):
    name = body.name or ""
    # RANJIVO: korisnički unos se ugrađuje u tekst predloška, pa Jinja2 izvršava {{ ... }} izraze.
    template = _env.from_string("Pozdrav, " + name + "!")
    return {"greeting": template.render()}
```

Dva su problema: (1) ranjiva verzija knjižnice i (2) interpolacija **korisničkog** unosa kao predloška. Oba
treba riješiti — nadogradnja bez promjene uporabe nije dovoljna, i obrnuto.

## 6. Popravak

1. Nadogradite `jinja2` u `requirements.txt` na `3.1.6` i ponovno instalirajte: `pip install -r
   requirements.txt`.
2. **Ne interpolirajte** korisnički unos: predložak je **konstanta**, a unos se predaje kao **podatak**
   (varijabla predloška) — `GREETING_TEMPLATE.render(name=...)`.

<details>
<summary>Referentno rješenje (grana <code>rjesenja</code>)</summary>

`requirements.txt`:
```
jinja2==3.1.6
```

`vulnshop/lab05/routes.py`:
```python
_env = SandboxedEnvironment()
# POPRAVAK: predložak je fiksan i ne sadrži korisnički unos.
GREETING_TEMPLATE = _env.from_string("Pozdrav, {{ name }}!")


@router.post("/api/lab05/greeting")
def greeting(body: GreetingRequest):
    # POPRAVAK: korisnički unos je podatak (varijabla), a ne dio predloška.
    return {"greeting": GREETING_TEMPLATE.render(name=body.name or "")}
```

</details>

## 7. Provjera popravka

### a) Testovi

```
pytest -m lab05
pytest -m "lab05 and security"
```

U PyCharmu: zeleni ▶ pokraj testne funkcije ili desni klik na `tests/lab05` → *Run 'pytest in lab05'*. U VS
Codeu: panel **Testing** (ikona tikvice/*flask*).

- `test_user_input_is_not_evaluated_as_template` – prije **PADA** (`{{ 7*7 }}` → `Pozdrav, 49!`), poslije
  **PROLAZI** (`Pozdrav, {{ 7*7 }}!`).
- `test_jinja2_version_is_not_vulnerable` – čita `importlib.metadata.version("jinja2")` i traži `>= 3.1.6`;
  **PADA** dok je instalirana 3.1.4, **PROLAZI** nakon nadogradnje.
- Funkcionalni `test_plain_greeting_works` (`Pozdrav, Ana!`) prolazi na obje grane.

> **Važno – reinstalacija.** Testovi version i SSTI ovise o **stvarno instaliranoj** verziji, ne samo o tekstu
> u `requirements.txt`. Nakon izmjene datoteke obavezno pokrenite `pip install -r requirements.txt`, inače
> rezultat testa ne odgovara promjeni. (Ako vam `test_jinja2_version_is_not_vulnerable` prolazi i prije nego
> što izmijenite `requirements.txt`, znači da u okruženju već imate instaliranu zakrpanu verziju — provjerite
> s `pip show jinja2`.)

### b) Ponovljeni napad

Svi payloadi iz koraka 4 sada ostaju **doslovni tekst**: `{{ 7*7 }}` → `Pozdrav, {{ 7*7 }}!`,
`{{ range(5)|list }}` → nepromijenjeno. Ime se ispisuje kao podatak, Jinja ga ne tumači.

### c) Ponovno skeniranje – otkrivanje ranjive ovisnosti

Konkretne naredbe nad ovim repozitorijem:

- **pip-audit (SCA):**
  ```
  pip-audit -r requirements.txt
  ```
  Na grani `main` izlistava `jinja2 3.1.4` s PYSEC/GHSA/CVE identifikatorima i *fix* verzijama
  (CVE-2024-56326 → 3.1.5, CVE-2024-56201 → 3.1.5, CVE-2025-27516 → 3.1.6); na `rjesenja`: „No known
  vulnerabilities found“.
- **OSV-Scanner:** `osv-scanner scan source -r .`
- **Trivy:** `trivy fs .`
- **GitHub Dependabot** / Dependency graph – automatsko upozorenje na CVE.
- Zastarjele ovisnosti: `pip list --outdated`.
- **SBOM (CycloneDX):** `cyclonedx-py requirements requirements.txt -o sbom.cdx.json`.
- Zaključavanje i integritet: točne verzije (pinovi), *hashevi*
  (`pip install --require-hashes -r requirements.txt`, `pip-compile --generate-hashes` iz `pip-tools` ili `uv
  lock`), pouzdan paketni indeks te oprez na *typosquatting* / *dependency confusion*.

## 8. Zadatak za samostalni rad

- Generirajte SBOM (`cyclonedx-py requirements requirements.txt -o sbom.cdx.json`) i **napišite dodatni pytest
  test** koji učita `sbom.cdx.json`, pronađe komponentu `jinja2` i tvrdi da joj je verzija `>= 3.1.6`
  (alternativa testu koji čita `importlib.metadata`).

**Pitanja za razmišljanje:**
1. Zašto nadogradnja verzije sama po sebi nije dovoljna ako i dalje interpoliramo korisnički unos?
2. Što je *tranzitivna* ovisnost i kako doći do popisa svih instaliranih (npr. `pip freeze`, stablo ovisnosti)?
3. Kako SBOM i zaključavanje s *hashevima* pomažu pri reakciji na novi 0-day u nekoj knjižnici?
