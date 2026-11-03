# Lab03 – SSRF (Server-Side Request Forgery)

## 1. Cilj vježbe

Pokazati kako funkcija „pregled poveznice“, koja dohvaća korisnički zadani URL, može natjerati poslužitelj da
pošalje zahtjev na interne resurse (loopback, cloud metadata) ili lokalne datoteke. Kod SSRF-a napadač
poslužitelj koristi kao **posrednika** prema zonama koje izvana ne vidi. Polaznik uvodi validaciju sheme i
odredišne adrese.

- **OWASP Top 10:2025:** A01 – Broken Access Control (SSRF je od 2025. dio A01)
- **CWE:** CWE-918 (*Server-Side Request Forgery*)

## 2. Gdje je kod

- `vulnshop/lab03/routes.py` – funkcija `preview(url, user)` → `GET /api/lab03/preview?url=`.
- Meta napada: ista datoteka, `internal_secrets(request)` → `GET /internal/admin/secrets` (vraća tajne SAMO
  kad zahtjev dolazi s loopback adrese; **nije predmet popravka**).
- `vulnshop/lab03/data.py` – vježba nema vlastitih tablica.
- Testovi: `tests/lab03/test_lab03_security.py` i `tests/lab03/test_lab03_functional.py`.

> **Zašto testovi koriste `live_server`.** Sigurnosni testovi koriste fixture `live_server` (stvarni uvicorn
> na slobodnom portu, vidi `tests/conftest.py`), jer se ranjivost vidi tek kad poslužitelj pošalje zahtjev
> **sam sebi** na loopback — što `TestClient` (bez prave mreže) ne bi reproducirao. Za `file://` test koristi
> privremenu datoteku i `Path.as_uri()` da radi i na Windowsu.

## 3. Opis ranjivosti

`preview` prima `url` i bez ikakve provjere otvara vezu (`urllib.request.urlopen`) te vraća prvih 2000
znakova. `urllib` podržava i `file://` i `ftp://`, a automatski slijedi i preusmjeravanja. Napadač može:

- dosegnuti **interni** endpoint na samom poslužitelju (`http://127.0.0.1:8000/internal/admin/secrets`),
- dohvatiti **cloud metadata** (`http://169.254.169.254/...`, čest izvor curenja ključeva u oblaku; stvarni
  slučaj: Capital One 2019.),
- čitati **lokalne datoteke** preko `file://`.

## 4. Eksploatacija – korak po korak

Pokrenite aplikaciju s `python -m vulnshop` (host `http://localhost:8000`). Gotovi zahtjevi su u
`http/lab03.http`; iste pozive možete izvesti i kroz **Swagger UI** na `http://localhost:8000/docs` (gumb
**Authorize**). Na Linuxu/macOS-u umjesto `curl.exe` pišete `curl`. Vrijednost `url` mora biti URL-enkodirana
— koristite gotove oblike iz `http/lab03.http` (`:` → `%3A`, `/` → `%2F`).

1. Prijavite se kao **ana** i zapamtite token.
2. **Napad na interni endpoint** preko loopbacka:
   ```
   curl.exe -s "http://localhost:8000/api/lab03/preview?url=http%3A%2F%2F127.0.0.1%3A8000%2Finternal%2Fadmin%2Fsecrets" -H "Authorization: Bearer <token>"
   ```
   **Očekivano (ranjivo):** `HTTP 200`, a `content` sadrži tajne:
   ```json
   {"url":"http://127.0.0.1:8000/internal/admin/secrets","content":"{\"dbPassword\":\"Sup3rTajn0!\",\"paymentApiKey\":\"sk_live_akademija_123\"}"}
   ```
   Interni endpoint je „vidio“ zahtjev s adrese 127.0.0.1 i povjerovao mu.
3. **Preko imena `localhost`** (`url=http%3A%2F%2Flocalhost%3A8000%2Finternal%2Fadmin%2Fsecrets`) — zaobilazi
   naivne provjere tipa „sadrži li URL 127.0.0.1“. Rezultat je isti `200` s tajnama.
4. **Cloud metadata:** `url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F`. Na lokalnom računalu obično
   istek vremena / `502`, ali u oblaku bi vratilo privremene vjerodajnice instance.
5. **`file://` shema:** `url=file%3A%2F%2F%2Fetc%2Fpasswd` (Linux/macOS) ili
   `url=file%3A%2F%2F%2FC%3A%2FWindows%2Fwin.ini` (Windows). **Očekivano (ranjivo):** `200` i sadržaj datoteke
   (`root:x:0:0:...`).

## 5. Analiza uzroka

```python
# RANJIVO: nikakva provjera sheme ni hosta. urllib podržava i file:// i ftp://,
# a automatski slijedi i preusmjeravanja (redirect).
with urllib.request.urlopen(url, timeout=5) as response:
    data = response.read(MAX_CHARS)
return {"url": url, "content": data.decode("utf-8", errors="replace")}
```

Nema allowliste shema, nema provjere da odredišna adresa nije interna, a slijede se i preusmjeravanja (vanjski
poslužitelj bi mogao preusmjeriti na `127.0.0.1`).

## 6. Popravak

- Dopustite samo sheme `http` i `https`.
- Razriješite host (`socket.getaddrinfo`) i provjerite **sve** dobivene adrese modulom `ipaddress`: odbijte
  loopback, privatne, link-local, unspecified, reserved, multicast i sve što nije `is_global` (uključujući
  IPv4-mapirani IPv6 oblik `::ffff:127.0.0.1`).
- Isključite slijeđenje preusmjeravanja (`httpx.get(..., follow_redirects=False, timeout=5)`), postavite
  timeout i vratite **400** za nedopušteno odredište. Po želji dodajte allowlistu domena.

> **Zaostali rizik (DNS rebinding / TOCTOU).** Provjera razrješava ime, a `httpx` ga razrješava **ponovno**
> pri spajanju — između te dvije točke DNS odgovor se može promijeniti (*time-of-check/time-of-use*).
> Robusnije je spojiti se **na već provjerenu IP adresu** (a `Host` zaglavlje postaviti na ime), uz *egress*
> vatrozid i, idealno, zaseban servis za dohvat u izoliranoj mreži.

<details>
<summary>Referentno rješenje (grana <code>rjesenja</code>)</summary>

```python
ALLOWED_SCHEMES = {"http", "https"}
# Po želji: allowlista domena (prazan skup = provjeravaju se samo adrese).
ALLOWED_DOMAINS: set[str] = set()


def is_forbidden_address(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])  # bez IPv6 zone (npr. fe80::1%eth0)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 -> 127.0.0.1
    return (
        ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_unspecified
        or ip.is_reserved or ip.is_multicast or not ip.is_global
    )


def validate_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise UnsafeUrlError("Dopuštene su samo sheme http i https.")
    host = parts.hostname
    if not host:
        raise UnsafeUrlError("URL nema host.")
    if ALLOWED_DOMAINS and host.lower() not in ALLOWED_DOMAINS:
        raise UnsafeUrlError("Domena nije na popisu dopuštenih.")
    try:
        port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
        addresses = {info[4][0] for info in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)}
    except (OSError, ValueError) as exc:
        raise UnsafeUrlError("Host nije moguće razriješiti.") from exc
    if not addresses or any(is_forbidden_address(address) for address in addresses):
        raise UnsafeUrlError("Odredište nije dopušteno (interna ili posebna adresa).")


@router.get("/api/lab03/preview")
def preview(url: str, user: CurrentUserDep):
    try:
        validate_url(url)
    except UnsafeUrlError as exc:
        return error(400, str(exc))
    try:
        response = httpx.get(url, follow_redirects=False, timeout=5)  # bez redirekata, uz timeout
    except httpx.HTTPError:
        return error(502, "Dohvat nije uspio.")
    if response.is_redirect:
        return error(400, "Preusmjeravanja nisu dopuštena.")
    return {"url": url, "content": response.text[:MAX_CHARS]}
```

</details>

## 7. Provjera popravka

### a) Testovi

```
pytest -m lab03
pytest -m "lab03 and security"
```

U PyCharmu: zeleni ▶ pokraj testne funkcije ili desni klik na `tests/lab03` → *Run 'pytest in lab03'*. U VS
Codeu: panel **Testing** (ikona tikvice/*flask*). Sigurnosni testovi dižu stvarni poslužitelj pa traju koju
sekundu dulje.

- **Prije popravka** padaju svi sigurnosni testovi: `test_ssrf_to_loopback_ip_is_blocked`,
  `test_ssrf_via_localhost_name_is_blocked`, `test_ssrf_to_ipv6_loopback_is_blocked`,
  `test_ssrf_to_cloud_metadata_is_blocked`, `test_file_scheme_is_blocked` (svi očekuju `400`, a dobiju
  `200`/`502`).
- **Poslije popravka** prolaze: sva odredišta vraćaju `400`, a tijelo više ne sadrži `Sup3rTajn0!`.
  Funkcionalni `test_unsupported_ftp_scheme_is_not_200` (ftp nije 200) i `test_without_token_returns_401`
  prolaze na obje grane.

### b) Ponovljeni napad

Svi napadi iz koraka 4 sada vraćaju **400**: loopback/`localhost`/`[::1]`/`169.254.169.254` →
`{"error":"Odredište nije dopušteno (interna ili posebna adresa)."}`, a `file://` i `ftp://` →
`{"error":"Dopuštene su samo sheme http i https."}`. Nepostojeći host daje
`{"error":"Host nije moguće razriješiti."}`.

### c) Ponovno skeniranje

- **Bandit** / **Ruff**: na grani `main` oba prijavljuju `urlopen` (`B310` / `S310`) u `vulnshop/lab03/routes.py`
  (`bandit -c pyproject.toml -r vulnshop`, `ruff check vulnshop --select S`). Nakon popravka (`httpx` uz
  validaciju) tog nalaza nema. Napomena: alat upozorava na `urlopen`, ali **ne** zna provjeravaju li se
  adrese — dokaz je u testu.
- **OWASP ZAP** / **Burp**: ručno fuzzanje `url` parametra listom internih adresa i portova.

## 8. Zadatak za samostalni rad

- Dodajte **allowlistu domena** (popunite `ALLOWED_DOMAINS`, npr. samo `akademija.span.hr`) i **napišite
  dodatni pytest test** koji potvrđuje da se dopuštena domena dohvaća, a sve ostalo odbija s `400`.

**Pitanja za razmišljanje:**
1. Zašto provjera samo URL stringa (bez DNS razrješavanja) nije dovoljna (*DNS rebinding*)?
2. Zašto je nužno blokirati preusmjeravanja i što bi se dogodilo da ih dopustimo?
3. Kako `169.254.169.254` može dovesti do potpune kompromitacije u oblaku i kako IMDSv2 to otežava?
