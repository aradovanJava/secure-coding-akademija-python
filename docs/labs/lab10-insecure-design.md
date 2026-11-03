# Lab10 – Insecure Design (poslovna logika)

## 1. Cilj vježbe

Pokazati propuste u dizajnu poslovne logike (povjerenje u cijenu i količinu s klijenta, višestruka primjena
istog kupona, nedostatak provjere stanja) te ih ispraviti autoritativnim izvorom podataka, validacijom i
transakcijom.

- **OWASP Top 10:2025:** A06 – Insecure Design
- **CWE:** CWE-840 (*Business Logic Errors*), CWE-20 (*Improper Input Validation*)

## 2. Gdje je kod

- `vulnshop/lab10/routes.py`
  - funkcija `wallet(user, db)` → `GET /api/lab10/wallet`
  - funkcija `checkout(body, user, db)` → `POST /api/lab10/checkout`
- Podaci: `vulnshop/lab10/data.py` — novčanici (svatko 1000.00 EUR: ana, marko, admin), proizvodi (1 Laptop 899.00, 2 Slušalice 99.00, 3 Kabel 9.99), tablica `lab10_coupon_usage`; kupon `AKADEMIJA10` = 10 %.
- Zajednička obrada validacijskih grešaka (Pydantic → `400`): `vulnshop/common/http.py`.
- Testovi: `tests/lab10/test_lab10_security.py`, `tests/lab10/test_lab10_functional.py`.

## 3. Opis ranjivosti

Poslužitelj vjeruje poljima `unitPrice` i `quantity` iz zahtjeva (dopušta i negativne), primjenjuje **svaki** kupon iz liste (pa i isti više puta) i mijenja stanje bez ikakve provjere. Posljedice:
- **negativna količina** → `unitPrice * quantity` je negativan → stanje novčanika **raste**,
- **lažna cijena** 0.01 za laptop → naplaćeno 0.01,
- **isti kupon 3×** → popust se slaže (0,9³).

## 4. Eksploatacija – korak po korak

Pokrenite aplikaciju s `python -m vulnshop` (host `http://localhost:8000`). Prijavite se i zapamtite token; zahtjevi su u `http/lab10.http`. U **Swagger UI-ju** na `http://localhost:8000/docs` kliknite **Authorize** i zalijepite token iz odgovora na `POST /api/auth/login`. Na Linuxu/macOS-u umjesto `curl.exe` pišete `curl`.

Prijava:

```
curl.exe -s -X POST http://localhost:8000/api/auth/login -H "Content-Type: application/json" -d "{\"username\":\"ana\",\"password\":\"Ana123!\"}"
```

Token iz odgovora šaljete kao `Authorization: Bearer <token>`. Stanje provjeravate s `GET /api/lab10/wallet` (seed 1000.00 EUR).

1. **Negativna količina povećava stanje:**

   ```json
   {"items":[{"productId":1,"quantity":-5,"unitPrice":899.00}],"couponCodes":[]}
   ```

   **Očekivano (ranjivo):** odgovor `{"charged":-4495.00,...}` — stanje novčanika **poraste** za 4495.00.
2. **Lažna cijena:** `quantity:1, unitPrice:0.01` za laptop → **Očekivano (ranjivo):** naplaćeno 0.01.
3. **Isti kupon 3×:** `couponCodes:["AKADEMIJA10","AKADEMIJA10","AKADEMIJA10"]` za slušalice (99.00) → **Očekivano (ranjivo):** naplaćeno 72.17 (99 × 0,9³) umjesto 99.00.

Primjer (korak 1), sa stvarnim tokenom:

```
curl.exe -s -X POST http://localhost:8000/api/lab10/checkout -H "Content-Type: application/json" -H "Authorization: Bearer <token>" -d "{\"items\":[{\"productId\":1,\"quantity\":-5,\"unitPrice\":899.00}],\"couponCodes\":[]}"
```

## 5. Analiza uzroka

```python
total = Decimal("0")
# RANJIVO: koriste se unitPrice i quantity iz zahtjeva (bez provjere predznaka i raspona).
for item in body.items:
    total += item.unit_price * item.quantity
# RANJIVO: svaki kupon iz liste primjenjuje se zasebno (može i više puta isti).
for coupon in body.coupon_codes or []:
    if coupon.upper() == COUPON_CODE:
        total *= COUPON_FACTOR
...
# RANJIVO: nema provjere total > 0 ni dostatnog stanja; negativan total povećava stanje.
new_balance = balance - total
```

Poslovna pravila (cijena, raspon količine, uporaba kupona, dostatnost sredstava) uopće se ne provode na poslužitelju — povjerenje je prepušteno klijentu.

## 6. Popravak

- Cijena se **uvijek** uzima iz baze; `unitPrice` iz zahtjeva se ignorira.
- Količina 1..10 preko Pydantic `Field(ge=1, le=10)` (neispravno → `400` kroz zajednički handler u `vulnshop/common/http.py`).
- Najviše jedan kupon i jednokratna uporaba po korisniku (tablica `lab10_coupon_usage`).
- Ukupan iznos mora biti > 0 i stanje novčanika mora biti dostatno.
- Sve provjere i promjene stanja unutar `with db.transaction():` — iznimka poništava sve (ROLLBACK).
- Napomena: modeliranje prijetnji (STRIDE — ovdje *Tampering*), *abuse cases* / *misuse stories*.

<details>
<summary>Referentno rješenje (grana <code>rjesenja</code>)</summary>

```python
class CheckoutItem(BaseModel):
    product_id: int = Field(alias="productId")
    quantity: int = Field(ge=1, le=10)                 # POPRAVAK: raspon validira Pydantic (-> 400)
    unit_price: Decimal | None = Field(default=None, alias="unitPrice")  # prima se, ali se IGNORIRA

class CheckoutRejected(Exception):
    """Narudžba krši poslovno pravilo (vraća se 400)."""

@router.post("/api/lab10/checkout")
def checkout(body: CheckoutRequest, user: CurrentUserDep, db: DbDep):
    coupons = body.coupon_codes or []
    if len(coupons) > 1:
        return error(400, "Dopušten je najviše jedan kupon.")
    try:
        with db.transaction():                          # sve ili ništa
            total = Decimal("0")
            for item in body.items:
                product = db.query_one("SELECT price FROM lab10_products WHERE id = ?", (item.product_id,))
                if product is None:
                    raise CheckoutRejected("Nepostojeći proizvod.")
                total += to_money(product["price"]) * item.quantity   # POPRAVAK: cijena IZ BAZE
            if coupons:
                if coupons[0].upper() != COUPON_CODE:
                    raise CheckoutRejected("Nepoznat kupon.")
                if db.query_one("SELECT 1 FROM lab10_coupon_usage WHERE username = ? AND coupon = ?",
                                 (user.username, COUPON_CODE)):
                    raise CheckoutRejected("Kupon je već iskorišten.")
                total *= COUPON_FACTOR
                db.execute("INSERT INTO lab10_coupon_usage (username, coupon) VALUES (?, ?)",
                           (user.username, COUPON_CODE))
            total = total.quantize(CENT, rounding=ROUND_HALF_UP)
            if total <= 0:
                raise CheckoutRejected("Neispravan ukupni iznos.")
            row = db.query_one("SELECT balance FROM lab10_wallets WHERE username = ?", (user.username,))
            balance = to_money(row["balance"])
            if balance < total:
                raise CheckoutRejected("Nedovoljno sredstava.")
            new_balance = balance - total
            db.execute("UPDATE lab10_wallets SET balance = ? WHERE username = ?", (new_balance, user.username))
    except CheckoutRejected as exc:
        return error(400, str(exc))                     # iznimka u bloku transaction() -> ROLLBACK
    return {"charged": total, "balance": new_balance}
```

</details>

## 7. Provjera popravka

### a) Testovi

```
pytest -m lab10
pytest -m "lab10 and security"
```

IDE: u PyCharmu kliknite zeleni ▶ pokraj testne funkcije (ili desni klik na `tests/lab10` → *Run 'pytest in lab10'*); u VS Codeu otvorite panel *Testing* (ikona tikvice) i pokrenite `tests/lab10`.

- **Prije popravka** padaju: `test_negative_quantity_is_rejected`, `test_client_price_is_ignored`, `test_repeated_coupon_is_not_stacked`.
- **Poslije popravka** svi prolaze: negativna količina → `400` (stanje nepromijenjeno), laptop se naplati 899.00 bez obzira na poslani `unitPrice`, a kupon se primijeni najviše jednom (ili `400`). Funkcionalni (`test_valid_checkout_reduces_balance` — 1× Kabel umanji stanje točno za 9.99) prolazi na obje grane.

> Testovi mjere **razliku** stanja novčanika (prije/poslije), a ne apsolutne vrijednosti, jer je instanca aplikacije (i baza) zajednička svim testovima — zato svaki test koristi svog korisnika i uspoređuje stanje prije i poslije.

### b) Ponovljeni napad

Nakon popravka: negativna količina i količina 11 vraćaju `400 {"error":"Neispravan zahtjev.","fields":["body.items.0.quantity"]}`; `unitPrice:0.01` naplati 899.00 (cijena iz baze); `["AKADEMIJA10"×3]` → `400 Dopušten je najviše jedan kupon.`; drugi pokušaj istog kupona → `400 Kupon je već iskorišten.`; checkout iznad stanja → `400 Nedovoljno sredstava.`. Legitiman checkout i dalje ispravno umanjuje stanje.

## 8. Zadatak za samostalni rad

- Dodajte provjeru maksimalnog iznosa narudžbe (npr. 5000.00 EUR) i **napišite dodatni pytest test** koji dokazuje da narudžba iznad granice vraća `400` i ne mijenja stanje novčanika (usporedbom stanja prije/poslije, kao postojeći sigurnosni testovi).

**Pitanja za razmišljanje:**
1. Zašto se cijena **nikad** ne smije uzeti s klijenta, čak ni radi „bržeg“ prikaza?
2. Kako biste modelirali *abuse case* za kupone (jednokratnost, trajanje, zabrana kombiniranja)?
3. Zašto je transakcija ovdje bitna i što bi se dogodilo da `INSERT` u `lab10_coupon_usage` i `UPDATE` novčanika nisu u istoj transakciji (vidi i Lab15)?
