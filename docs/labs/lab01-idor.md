# Lab01 – IDOR (Insecure Direct Object Reference)

## 1. Cilj vježbe

Naučiti prepoznati i ispraviti **Broken Access Control** tipa IDOR: aplikacija dohvaća objekt po
identifikatoru iz zahtjeva, ali ne provjerava smije li ga baš taj korisnik vidjeti. Polaznik eksploatira
ranjivost, analizira uzrok, dodaje provjeru vlasništva i piše jedinični test.

- **OWASP Top 10:2025:** A01 – Broken Access Control
- **CWE:** CWE-639 (*Authorization Bypass Through User-Controlled Key*)

## 2. Gdje je kod

- `vulnshop/lab01/routes.py` – funkcija `get_order(order_id, user, db)` → `GET /api/lab01/orders/{order_id}`.
- Početni podaci: `vulnshop/lab01/data.py`, tablica `lab01_orders` (narudžbe 1001, 1002 = *ana*; 1003 =
  *marko*; 1004 = *admin*).
- Testovi: `tests/lab01/test_lab01_security.py` i `tests/lab01/test_lab01_functional.py`.

## 3. Opis ranjivosti

Endpoint vraća narudžbu isključivo na temelju `order_id` iz URL-a. Identifikatori su predvidljivi (redni
brojevi), pa prijavljeni korisnik samo promijeni broj u URL-u i čita tuđe narudžbe (imena, adrese, iznose).
To je jedan od najčešćih propusta u stvarnim aplikacijama (poznati slučajevi curenja računa i narudžbi
mijenjanjem ID-a u URL-u).

## 4. Eksploatacija – korak po korak

Pokrenite aplikaciju s `python -m vulnshop` (host `http://localhost:8000`). Gotovi zahtjevi su u
`http/lab01.http`; iste pozive možete izvesti i kroz **Swagger UI** na `http://localhost:8000/docs` (gumb
**Authorize** gore desno, zalijepite token). Na Linuxu/macOS-u umjesto `curl.exe` pišete `curl`.

1. Prijavite se kao **ana** i zapamtite token iz odgovora:
   ```
   curl.exe -s -X POST http://localhost:8000/api/auth/login -H "Content-Type: application/json" -d "{\"username\":\"ana\",\"password\":\"Ana123!\"}"
   ```
2. Legitimno – dohvat vlastite narudžbe 1001 (`200`):
   ```
   curl.exe -s http://localhost:8000/api/lab01/orders/1001 -H "Authorization: Bearer <token>"
   ```
3. **Napad** – istim tokenom dohvatite Markovu narudžbu 1003:
   ```
   curl.exe -s http://localhost:8000/api/lab01/orders/1003 -H "Authorization: Bearer <token>"
   ```
   **Očekivano (ranjivo):** `HTTP 200` i Markovi podaci iako ste prijavljeni kao ana → dokaz IDOR-a:
   ```json
   {"id":1003,"owner":"marko","items":"Monitor","shippingAddress":"Savska 10, Zagreb","total":299.0}
   ```

## 5. Analiza uzroka

```python
if row is None:
    return error(404, "Narudžba nije pronađena.")
# RANJIVO: ne provjerava se je li prijavljeni korisnik vlasnik narudžbe niti je li ADMIN.
return to_dto(row)
```

Nedostaje autorizacijska provjera: je li `row["owner_username"]` jednak `user.username` ili je korisnik
administrator (`user.is_admin`). Autentikacija (tko si) postoji, ali autorizacija (što smiješ) ne.

## 6. Popravak

Dodajte provjeru vlasništva. Ako narudžba nije korisnikova, a korisnik nije ADMIN, vratite **404** (ne 403) —
tako ne otkrivamo ni postojanje tuđe narudžbe i sprječavamo enumeraciju.

<details>
<summary>Referentno rješenje (grana <code>rjesenja</code>)</summary>

```python
@router.get("/api/lab01/orders/{order_id}")
def get_order(order_id: int, user: CurrentUserDep, db: DbDep):
    row = db.query_one(
        "SELECT id, owner_username, items, shipping_address, total FROM lab01_orders WHERE id = ?",
        (order_id,),
    )
    # POPRAVAK: provjera vlasništva. Tuđa narudžba izgleda isto kao nepostojeća (404),
    # osim za administratora koji smije vidjeti sve narudžbe.
    if row is None or (row["owner_username"] != user.username and not user.is_admin):
        return error(404, "Narudžba nije pronađena.")
    return to_dto(row)
```

</details>

## 7. Provjera popravka

### a) Testovi

```
pytest -m lab01
pytest -m "lab01 and security"
```

U PyCharmu: zeleni ▶ pokraj testne funkcije ili desni klik na `tests/lab01` → *Run 'pytest in lab01'*. U VS
Codeu: panel **Testing** (ikona tikvice/*flask*).

- **Prije popravka** pada `test_ana_cannot_read_other_users_order` (ana dohvati 1003 i dobije `200`).
- **Poslije popravka** prolazi (ana → `404`). Funkcionalni `test_ana_can_read_own_order` (1001 → 200),
  `test_admin_can_read_any_order` (admin → 1003 → 200) i `test_without_token_returns_401` prolaze na obje grane.

### b) Ponovljeni napad

`GET /api/lab01/orders/1003` kao ana sada vraća **404** `{"error":"Narudžba nije pronađena."}` — jednako kao
za nepostojeću narudžbu 9999. Vlastita 1001 i dalje radi (`200`), a admin smije sve (`200`).

### c) Ponovno skeniranje

IDOR je logička ranjivost koju statička analiza (Bandit, Ruff `--select S`) u pravilu **ne** otkriva — nema
„opasnog“ poziva, nego nedostaje provjera. Dinamički se traži alatom poput **OWASP ZAP** (*Access Control
Testing* uz dvije uloge) ili ručno u Burpu zamjenom ID-a. Zato je jedinični test ključan dokaz popravka.

## 8. Zadatak za samostalni rad

- Dodajte endpoint `GET /api/lab01/orders` koji vraća **samo** narudžbe trenutnog korisnika i **napišite
  dodatni pytest test** koji potvrđuje da ana vidi točno 2 narudžbe, a marko 1.

**Pitanja za razmišljanje:**
1. Zašto je kod IDOR-a bolje vratiti 404 nego 403?
2. Kako biste spriječili enumeraciju identifikatora (npr. UUID umjesto rednih brojeva) i koja su ograničenja te mjere?
3. Gdje u slojevitoj arhitekturi (ruta / servis / repozitorij) pripada autorizacijska provjera?
