# Lab13 – Nesigurna deserijalizacija

## 1. Cilj vježbe

Pokazati zašto je deserijalizacija nepouzdanih Python objekata modulom `pickle` opasna (izvršavanje koda
tijekom `pickle.loads`), te kako je ograničiti allowlistom klasa (ili, bolje, prijeći na JSON/DTO).

- **OWASP Top 10:2025:** A08 – Software or Data Integrity Failures
- **CWE:** CWE-502 (Deserialization of Untrusted Data)

## 2. Gdje je kod

- `vulnshop/lab13/routes.py` → endpoint `POST /api/lab13/cart/import` (tijelo je Base64 zapis `Cart`
  objekta serijaliziranog modulom `pickle`).
- `vulnshop/lab13/models.py` – legitimne klase `Cart` i `CartItem` te „gadget" klasa `DiagnosticsTask`
  (njezina metoda `__setstate__` izvršava se tijekom deserijalizacije i zapisuje bezopasnu marker datoteku).
- Pomoćni alat za payloade: `tests/lab13/payloads.py` (pokretanje: `python -m tests.lab13.payloads`).
- Testovi: `tests/lab13/test_lab13_security.py` i `tests/lab13/test_lab13_functional.py`.

## 3. Opis ranjivosti

`import_cart` poziva `pickle.loads(data)` nad podatkom koji dolazi od klijenta, bez ikakvog ograničenja.
`pickle` pri deserijalizaciji može **instancirati bilo koju klasu** i **pozvati bilo koju funkciju**, pa
napadač ne šalje košaricu nego objekt koji izvršava kod već **tijekom** `pickle.loads`, prije nego aplikacija
uopće provjeri tip.

Konceptualno (bez koda payloada): u Pythonu napadaču **nije potrebna** ni posebna „gadget" klasa – svaki
objekt može definirati metodu `__reduce__` kojom pri deserijalizaciji pickle pozove proizvoljan *callable*
(npr. `os.system`). Zato službena Python dokumentacija izričito upozorava da se **nikad** ne smije
*unpickle*-ati podatke iz nepouzdanog izvora. Klasa `DiagnosticsTask` u ovoj vježbi postoji samo zato da
demonstracija ostane bezopasna: umjesto pokretanja procesa, zapisuje kratku tekstualnu (marker) datoteku.

## 4. Eksploatacija – korak po korak

> Pokreni aplikaciju s `python -m vulnshop` (`http://localhost:8000`, Swagger UI na
> `http://localhost:8000/docs`). Na Linuxu/macOS-u umjesto `curl.exe` pišeš `curl`.

1. **Generiraj payloade.** Iz korijena repozitorija pokreni pomoćni alat (on **nije** napadačka skripta nego
   generator Base64 sadržaja za vježbu):
   ```bash
   python -m tests.lab13.payloads
   ```
   U VS Codeu isto radi konfiguracija za pokretanje **„Lab13: ispisi payload (Base64)"**. Alat ispisuje dva
   Base64 niza: legitimnu košaricu (2 stavke) i napadački `DiagnosticsTask` (ciljna marker datoteka je u
   privremenom direktoriju, npr. `lab13-pwned.txt`). Kopiraj ih u `http/lab13.http`.
2. **Napad:** pošalji napadački payload kao tijelo zahtjeva:
   ```bash
   curl.exe -s -X POST http://localhost:8000/api/lab13/cart/import -H "Content-Type: text/plain" -d "<ATTACK_BASE64>"
   ```
   **Očekivano (ranjivo):** odgovor **200** `{"status":"ok","type":"DiagnosticsTask"}` i **marker datoteka
   nastane** na zadanoj putanji → dokaz da se kod izvršio tijekom deserijalizacije (iako objekt nikad nije
   bio košarica).
3. Za usporedbu pošalji legitimnu košaricu → **200** `{"status":"ok","itemCount":2}`.

## 5. Analiza uzroka

```python
@router.post("/api/lab13/cart/import")
async def import_cart(request: Request):
    body = (await request.body()).decode("ascii", errors="replace").strip()
    try:
        data = base64.b64decode(body, validate=True)
        # RANJIVO: pickle.loads bez ograničenja deserijalizira BILO KOJU klasu i poziva njezin kod.
        obj = pickle.loads(data)
    except Exception:
        return error(400, "Neispravan sadržaj košarice.")
    if isinstance(obj, Cart):
        return {"status": "ok", "itemCount": len(obj.items)}
    return {"status": "ok", "type": type(obj).__name__}
```

Provjera tipa `isinstance(obj, Cart)` dolazi **prekasno** – `pickle.loads` je već stvorio objekt i izvršio
njegov kod (`__setstate__`/`__reduce__`). Deserijalizacija nepouzdanih podataka je sama po sebi izvršavanje
koda pod kontrolom napadača.

## 6. Popravak

- Ograniči `Unpickler`: nadjačaj `find_class` tako da dopušta **samo** klase `Cart` i `CartItem`; svaka druga
  klasa ili funkcija (`DiagnosticsTask`, `os.system`, `builtins.eval` …) odbija se **prije** izvršavanja.
- Ograniči veličinu sadržaja (npr. 10 000 B) i provjeri tip rezultata.
- **Fail-closed:** bilo kakva greška pri deserijalizaciji = odbijanje (400).
- Najbolje rješenje: za podatke od klijenta uopće ne koristiti `pickle`, nego **JSON + Pydantic DTO**. Ako
  binarni format mora ostati, podatke dodatno **potpisati (HMAC)** kako bi poslužitelj prihvaćao samo ono što
  je sam izdao.

<details>
<summary>Referentno rješenje (grana <code>rjesenja</code>)</summary>

```python
MAX_PAYLOAD_BYTES = 10_000
ALLOWED_CLASSES = {
    ("vulnshop.lab13.models", "Cart"): Cart,
    ("vulnshop.lab13.models", "CartItem"): CartItem,
}


class RestrictedUnpickler(pickle.Unpickler):
    """POPRAVAK: allowlista klasa koje se smiju deserijalizirati."""

    def find_class(self, module: str, name: str):
        allowed = ALLOWED_CLASSES.get((module, name))
        if allowed is None:
            raise pickle.UnpicklingError(f"Klasa nije dopuštena: {module}.{name}")
        return allowed


def safe_loads(data: bytes) -> object:
    return RestrictedUnpickler(io.BytesIO(data)).load()


@router.post("/api/lab13/cart/import")
async def import_cart(request: Request):
    raw = await request.body()
    if len(raw) > MAX_PAYLOAD_BYTES:
        return error(400, "Sadržaj je prevelik.")
    try:
        data = base64.b64decode(raw.decode("ascii").strip(), validate=True)
        cart = safe_loads(data)
    except Exception:
        # Fail-closed: bilo kakva greška pri deserijalizaciji nepouzdanih podataka = odbijanje.
        return error(400, "Neispravan sadržaj košarice.")
    items = getattr(cart, "items", None)
    if not isinstance(cart, Cart) or not isinstance(items, list) or not all(isinstance(i, CartItem) for i in items):
        return error(400, "Neispravan sadržaj košarice.")
    return {"status": "ok", "itemCount": len(cart.items)}
```

</details>

## 7. Provjera popravka

### (a) Testovi

```bash
pytest -m lab13
pytest -m "lab13 and security"
```

U PyCharmu: zelena strelica ▶ pokraj funkcije testa, ili desni klik na `tests/lab13` → *Run 'pytest in
lab13'*. U VS Codeu: panel **Testing** (ikona tikvice/*flask*).

- `test_attack_payload_is_rejected_and_has_no_effect` – prije **PADA** (napadački payload → 200 i marker
  datoteka u `tmp_path` nastane), poslije **PROLAZI** (→ 400, marker datoteka **ne** nastane jer se klasa
  odbija prije izvršavanja).
- Funkcionalni `test_legitimate_cart_is_imported` (legitimna košarica, 2 stavke → 200, `itemCount=2`) prolazi
  na obje grane.

### (b) Ponovljeni napad

Nakon popravka napad iz koraka 4.2 vraća **400** `{"error":"Neispravan sadržaj košarice."}` i marker datoteka
**ne** nastaje, jer `RestrictedUnpickler.find_class` odbija `DiagnosticsTask` prije pozivanja njezina koda.

### (c) Alati

- **Bandit:** `bandit -c pyproject.toml -r vulnshop` prijavljuje `B403` (uvoz `pickle`) i `B301`
  (`pickle.loads`).
- **Ruff:** `ruff check vulnshop --select S` prijavljuje `S301` na `pickle.loads`.
- **Semgrep** / **OWASP ZAP** također prepoznaju nesigurnu deserijalizaciju.

## 8. Zadatak za samostalni rad

- Napiši dodatni pytest test koji provjerava da payload s **dopuštenim** klasama, ali prevelik (> 10 000 B),
  biva odbijen s **400** (granica veličine), a da legitimna mala košarica i dalje prolazi.

Pitanja za razmišljanje:

1. Zašto provjera tipa `isinstance(...)` **nakon** `pickle.loads` ne pomaže, i zašto filtar mora djelovati
   unutar `find_class`?
2. Što znači da napadaču u Pythonu nije potrebna „gadget" klasa (uloga `__reduce__`)?
3. Kada je, umjesto allowliste, bolje potpuno napustiti `pickle` i prijeći na JSON + DTO, a kada je potreban
   HMAC potpis binarnih podataka?
