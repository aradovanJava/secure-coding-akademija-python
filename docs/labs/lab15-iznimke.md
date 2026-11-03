# Lab15 – Mishandling of Exceptional Conditions

## 1. Cilj vježbe

Pokazati tri posljedice lošeg rukovanja iznimkama: fail-open sigurnosne provjere, nedostatak transakcije
(nekonzistentno stanje) i curenje detalja greške. Polaznik uvodi fail-closed, transakciju i generički
odgovor.

- **OWASP Top 10:2025:** A10 – Mishandling of Exceptional Conditions
- **CWE:** CWE-636 (Not Failing Securely / „fail open"), CWE-755 (Improper Handling of Exceptional Conditions), CWE-209 (Information Exposure Through an Error Message), CWE-460 (Improper Cleanup on Thrown Exception)

## 2. Gdje je kod

- `vulnshop/lab15/routes.py` → endpointi `GET /api/lab15/accounts` i `POST /api/lab15/transfer`
  (funkcija `transfer`).
- `vulnshop/lab15/limit_service.py` – klasa `LimitService`, metoda `check(amount, currency)` (baca iznimku za
  nepoznatu valutu, neispravan iznos ili prekoračen dnevni limit).
- `vulnshop/lab15/data.py` – seed tablice `lab15_accounts`: `HR-ANA-001` (ana, 5000), `HR-MARKO-001`
  (marko, 1000), `HR-ADMIN-001` (admin, 10000).
- Transakcijski kontekst `db.transaction()` je u `vulnshop/common/db.py` (ROLLBACK pri iznimci).
- Testovi: `tests/lab15/test_lab15_security.py` i `tests/lab15/test_lab15_functional.py` (mjere **razliku**
  salda prije/poslije).

## 3. Opis ranjivosti

```python
try:
    limit_service.check(amount, body.currency)
except Exception as exc:
    log.debug("Provjera limita nije uspjela, nastavljam svejedno: %s", exc)  # FAIL-OPEN
```

- **Fail-open (CWE-636):** iznimka iz provjere limita se „proguta", pa transfer 50000 s valutom `XYZ` prođe.
- **Bez transakcije (CWE-460/CWE-755):** terećenje i odobrenje izvode se zasebno; ako odredišni račun ne
  postoji, terećenje se **ne** poništi → novac nestane.
- **Curenje (CWE-209):** poruka greške vraća puni naziv klase iznimke, naziv tablice i SQL.

## 4. Eksploatacija – korak po korak

> Pokreni aplikaciju s `python -m vulnshop` (`http://localhost:8000`, Swagger UI na
> `http://localhost:8000/docs`). Prvo se prijavi i zapamti token (vidi `http/lab15.http`). Na Linuxu/macOS-u
> umjesto `curl.exe` pišeš `curl`.

```bash
curl.exe -s -X POST http://localhost:8000/api/auth/login -H "Content-Type: application/json" -d "{\"username\":\"ana\",\"password\":\"Ana123!\"}"
```

Token iz odgovora šalji kao `Authorization: Bearer <token>`.

1. **Fail-open:** transfer iznad limita s nedopuštenom valutom:
   ```bash
   curl.exe -s -X POST http://localhost:8000/api/lab15/transfer -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d "{\"fromAccount\":\"HR-ANA-001\",\"toAccount\":\"HR-MARKO-001\",\"amount\":\"50000.00\",\"currency\":\"XYZ\"}"
   ```
   **Očekivano (ranjivo):** **200** `{"status":"izvršeno","amount":50000.0}`, a saldo računa `HR-ANA-001`
   padne na **-45000.00** iako valuta nije dopuštena i iznos je daleko iznad limita.
2. **Gubitak novca (bez transakcije):** transfer na nepostojeći račun:
   ```bash
   curl.exe -s -X POST http://localhost:8000/api/lab15/transfer -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d "{\"fromAccount\":\"HR-ANA-001\",\"toAccount\":\"HR-NEPOSTOJI-999\",\"amount\":\"100.00\",\"currency\":\"EUR\"}"
   ```
   **Očekivano (ranjivo):** **500** s tijelom koje otkriva detalje:
   `{"error":"builtins.LookupError: Odredišni račun HR-NEPOSTOJI-999 ne postoji u tablici lab15_accounts (UPDATE lab15_accounts SET balance = balance + ? WHERE account_no = ?)"}`.
   Saldo ane se ipak smanji za 100 (terećenje nije poništeno) → novac nestane.
3. **Curenje kroz neispravan iznos:** pošalji `"amount":"abc"`. **Očekivano (ranjivo):** **500**
   `{"error":"decimal.InvalidOperation: [<class 'decimal.ConversionSyntax'>]"}` – odgovor otkriva internu
   klasu iznimke.

## 5. Analiza uzroka

```python
try:
    amount = Decimal(body.amount)
    try:
        limit_service.check(amount, body.currency)
    except Exception as exc:
        log.debug("Provjera limita nije uspjela, nastavljam svejedno: %s", exc)  # FAIL-OPEN

    db.execute("UPDATE lab15_accounts SET balance = balance - ? WHERE account_no = ?", (amount, body.from_account))
    updated = db.execute("UPDATE lab15_accounts SET balance = balance + ? WHERE account_no = ?", (amount, body.to_account))
    if updated == 0:
        raise LookupError(f"Odredišni račun {body.to_account} ne postoji u tablici lab15_accounts ...")  # bez rollbacka
    return {"status": "izvršeno", "amount": amount}
except Exception as exc:
    # RANJIVO: vraća se naziv klase iznimke i detaljna poruka (naziv tablice, SQL).
    return error(500, f"{type(exc).__module__}.{type(exc).__qualname__}: {exc}")
```

Sigurnosna provjera koja „pukne" tretira se kao uspjeh (fail-open); višekoračna izmjena stanja nije u
transakciji; globalni `except` vraća interne detalje klijentu.

## 6. Popravak

- **Fail-closed:** svaka iznimka u sigurnosnoj provjeri = odbijanje (400), bez izvršavanja transfera.
- Validacija ulaza unaprijed: iznos kao `Decimal` (konačan, > 0, najviše dvije decimale), valuta s dopuštenog
  popisa (preko `LimitService`), izvorišni račun mora pripadati prijavljenom korisniku i imati dovoljno
  sredstava.
- **Transakcija** (`with db.transaction():`): terećenje i odobrenje zajedno; iznimka → ROLLBACK poništi i
  terećenje.
- Generička poruka + `correlationId` u tijelu (400); tehnički detalji idu **samo** u log.

<details>
<summary>Referentno rješenje (grana <code>rjesenja</code>)</summary>

```python
class TransferRejected(Exception):
    """Transfer se odbija (vraća se 400 s generičkom porukom)."""


def parse_amount(value: str | None) -> Decimal:
    try:
        amount = Decimal(value or "")
    except InvalidOperation as exc:
        raise TransferRejected("Neispravan iznos.") from exc
    if not amount.is_finite() or amount <= 0 or amount != amount.quantize(Decimal("0.01")):
        raise TransferRejected("Neispravan iznos.")
    return amount


@router.post("/api/lab15/transfer")
def transfer(body: TransferRequest, user: CurrentUserDep, db: DbDep):
    correlation_id = str(uuid.uuid4())
    try:
        amount = parse_amount(body.amount)                       # validacija unaprijed
        if not body.from_account or not body.to_account or body.from_account == body.to_account:
            raise TransferRejected("Neispravni podaci o računima.")
        try:
            limit_service.check(amount, body.currency)           # FAIL-CLOSED
        except Exception as exc:
            log.warning("Transfer odbijen (provjera limita) correlationId=%s razlog=%s", correlation_id, exc)
            raise TransferRejected("Transfer nije dopušten.") from exc
        with db.transaction():                                   # terećenje + odobrenje atomski
            source = db.query_one(
                "SELECT balance FROM lab15_accounts WHERE account_no = ? AND owner_username = ?",
                (body.from_account, user.username),
            )
            if source is None:
                raise TransferRejected("Izvorišni račun nije dostupan.")
            if to_money(source["balance"]) < amount:
                raise TransferRejected("Nedovoljno sredstava.")
            db.execute("UPDATE lab15_accounts SET balance = balance - ? WHERE account_no = ?", (amount, body.from_account))
            updated = db.execute("UPDATE lab15_accounts SET balance = balance + ? WHERE account_no = ?", (amount, body.to_account))
            if updated == 0:
                raise TransferRejected("Transfer nije moguće izvršiti.")  # -> ROLLBACK
    except TransferRejected as exc:
        # Generička poruka + korelacijski ID, bez tehničkih detalja.
        return JSONResponse(status_code=400, content={"error": str(exc), "correlationId": correlation_id})
    return {"status": "izvršeno", "amount": amount}
```

</details>

## 7. Provjera popravka

### (a) Testovi

```bash
pytest -m lab15
pytest -m "lab15 and security"
```

U PyCharmu: zelena strelica ▶ pokraj funkcije testa, ili desni klik na `tests/lab15` → *Run 'pytest in
lab15'*. U VS Codeu: panel **Testing** (ikona tikvice/*flask*). Testovi mjere **razliku** salda prije i
poslije poziva.

- `test_unknown_currency_fails_closed` – prije **PADA** (50000 XYZ prođe, saldo se promijeni), poslije
  **PROLAZI** (→ 4xx, saldo nepromijenjen).
- `test_transfer_to_missing_account_keeps_balance` – prije **PADA** (terećenje ostaje, novac nestane),
  poslije **PROLAZI** (→ 4xx, saldo nepromijenjen zbog ROLLBACK-a).
- `test_error_body_does_not_leak_details` – prije **PADA** (tijelo sadrži `decimal` / `builtins` /
  `lab15_accounts` / `UPDATE`), poslije **PROLAZI** (generička poruka, bez detalja).
- Funkcionalni `test_valid_transfer_reduces_balance` (100 EUR → 200, saldo -100) prolazi na obje grane.

### (b) Ponovljeni napad

Nakon popravka napadi iz koraka 4 vraćaju **400** s generičkom porukom i `correlationId`, npr.
`{"error":"Transfer nije dopušten.","correlationId":"..."}` (XYZ),
`{"error":"Transfer nije moguće izvršiti.","correlationId":"..."}` (nepostojeći račun) i
`{"error":"Neispravan iznos.","correlationId":"..."}` (`amount:"abc"`). Saldo ostaje nepromijenjen jer je sve
unutar transakcije.

### (c) Alati

- **Ruff:** `ruff check vulnshop --select S` prijavljuje `S608`, a **Bandit** (`bandit -c pyproject.toml -r
  vulnshop`) `B608` na ranjivoj poruci greške jer sadrži SQL tekst. To je **lažno pozitivno** kao SQL
  injection (riječ je o tekstu iznimke, ne o upitu), ali ispravno upire u stvaran problem – **curenje
  informacija**. Dobar trenutak za vježbu *triažiranja* nalaza alata: razlikovati vrstu propusta koju alat
  prijavljuje od stvarne koja postoji.

## 8. Zadatak za samostalni rad

- Napiši dodatni pytest test koji provjerava da transfer iznosa s više od dvije decimale (npr. `"100.123"`)
  biva odbijen s **400** i da saldo ostaje nepromijenjen.

Pitanja za razmišljanje:

1. Što znači „fail securely" i zašto je zadano ponašanje sigurnosne provjere „odbij"?
2. Zašto višekoračne izmjene stanja moraju biti atomske (transakcija), i što bi se dogodilo bez `with
   db.transaction()`?
3. Kako korelacijski ID pomaže podršci i istrazi, a da se korisniku ne otkrivaju interni detalji?
