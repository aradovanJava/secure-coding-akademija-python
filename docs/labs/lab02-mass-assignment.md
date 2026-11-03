# Lab02 – Mass assignment / eskalacija privilegija

## 1. Cilj vježbe

Pokazati kako slijepo vezivanje (*binding*) cijelog JSON tijela na model omogućuje korisniku da postavi
polje koje ne bi smio (npr. `role`) i tako eskalira privilegije. Polaznik uvodi DTO sa samo dopuštenim
poljima i validaciju.

- **OWASP Top 10:2025:** A01 – Broken Access Control
- **CWE:** CWE-915 (*Improperly Controlled Modification of Dynamically-Determined Object Attributes*), CWE-269 (*Improper Privilege Management*)

## 2. Gdje je kod

- `vulnshop/lab02/routes.py` – Pydantic model `ProfileUpdate` i funkcija `update_profile(update, user, db)`;
  endpointi `PUT /api/lab02/profile`, `GET /api/lab02/profile`, `GET /api/lab02/admin/users`.
- Početni podaci: `vulnshop/lab02/data.py`, tablica `lab02_profiles(user_id, display_name, email, role)`.
- Testovi: `tests/lab02/test_lab02_security.py` i `tests/lab02/test_lab02_functional.py`.

## 3. Opis ranjivosti

Model `ProfileUpdate` sadrži i polje `role`, a `PUT /profile` ga preko `COALESCE(?, role)` zapisuje u bazu.
Administratorska ovlast (`GET /admin/users`) provjerava se prema `role` iz iste tablice. Dakle korisnik može
poslati `"role":"ADMIN"`, promijeniti si vlastitu ulogu i dobiti administratorski pristup. Legitimni klijent
`role` ne šalje (`COALESCE` tada zadržava staru vrijednost), ali napadaču nitko ne brani da ga pošalje.

## 4. Eksploatacija – korak po korak

Pokrenite aplikaciju s `python -m vulnshop` (host `http://localhost:8000`). Gotovi zahtjevi su u
`http/lab02.http`; iste pozive možete izvesti i kroz **Swagger UI** na `http://localhost:8000/docs` (gumb
**Authorize**). Na Linuxu/macOS-u umjesto `curl.exe` pišete `curl`.

1. Prijavite se kao **marko** (`Marko123!`) i zapamtite token.
2. Provjerite profil – `GET /api/lab02/profile` → `role: USER`.
3. **Napad** – pošaljite PUT s ulogom ADMIN:
   ```
   curl.exe -s -X PUT http://localhost:8000/api/lab02/profile -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d "{\"displayName\":\"Marko\",\"email\":\"m@x.hr\",\"role\":\"ADMIN\"}"
   ```
   **Očekivano (ranjivo):** odgovor je `{"userId":2,"displayName":"Marko","email":"m@x.hr","role":"ADMIN"}`.
4. Pristupite admin popisu – `GET /api/lab02/admin/users`:
   ```
   curl.exe -s http://localhost:8000/api/lab02/admin/users -H "Authorization: Bearer <token>"
   ```
   **Očekivano (ranjivo):** `HTTP 200` i popis svih profila (prije napada taj je poziv vraćao `403`).

## 5. Analiza uzroka

```python
class ProfileUpdate(BaseModel):
    """RANJIVO: model prihvaća i polje role iz tijela zahtjeva."""
    display_name: str | None = Field(default=None, alias="displayName")
    email: str | None = None
    role: str | None = None

# RANJIVO: role dolazi izravno iz JSON-a i zapisuje se bez provjere (mass assignment).
db.execute(
    "UPDATE lab02_profiles SET display_name = COALESCE(?, display_name), email = COALESCE(?, email), "
    "role = COALESCE(?, role) WHERE user_id = ?",
    (update.display_name, update.email, update.role, user.id),
)
```

Model sadrži `role` i prosljeđuje ga u `UPDATE`. Korisnik time kontrolira polje koje bi smio mijenjati samo
administrator, i to kroz poseban proces.

## 6. Popravak

DTO smije sadržavati **samo** polja koja korisnik smije mijenjati (`displayName`, `email`), uz validaciju.
Uloga se kroz ovaj endpoint ne dira. U Pydanticu je korisno:

- `model_config = ConfigDict(extra="ignore")` – nepoznata polja (npr. `role`) se tiho odbacuju (ili
  `extra="forbid"` ako želite i odbiti zahtjev sa `400`);
- validacija kroz `Field(min_length=..., max_length=..., pattern=...)`;
- `alias="displayName"` za vanjski naziv polja;
- kao dobra praksa, **odvojeni** ulazni i izlazni model (`response_model`) da se slučajno ne vrati više nego
  što treba.

<details>
<summary>Referentno rješenje (grana <code>rjesenja</code>)</summary>

```python
class ProfileUpdate(BaseModel):
    """POPRAVAK: DTO samo s poljima koja korisnik smije mijenjati (bez role) + validacija."""

    model_config = ConfigDict(extra="ignore")  # nepoznata polja (npr. "role") se odbacuju

    display_name: str = Field(alias="displayName", min_length=1, max_length=100)
    email: str = Field(max_length=200, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@router.put("/api/lab02/profile")
def update_profile(update: ProfileUpdate, user: CurrentUserDep, db: DbDep):
    # POPRAVAK: zapisuju se samo dopuštena polja; uloga se ovdje ne može promijeniti.
    db.execute(
        "UPDATE lab02_profiles SET display_name = ?, email = ? WHERE user_id = ?",
        (update.display_name, update.email, user.id),
    )
    return to_dto(load_profile(db, user.id))
```

Promjena uloge ide isključivo kroz zaseban administratorski proces.

</details>

## 7. Provjera popravka

### a) Testovi

```
pytest -m lab02
pytest -m "lab02 and security"
```

U PyCharmu: zeleni ▶ pokraj testne funkcije ili desni klik na `tests/lab02` → *Run 'pytest in lab02'*. U VS
Codeu: panel **Testing** (ikona tikvice/*flask*).

- **Prije popravka** padaju `test_marko_cannot_make_himself_admin` (profil postane ADMIN) i
  `test_marko_has_no_access_to_admin_users` (`/admin/users` → 200).
- **Poslije popravka** prolaze: nakon PUT-a s `role=ADMIN` profil i dalje ima `USER`, a `/admin/users` → `403`.
  Funkcionalni `test_ana_can_change_display_name` i `test_admin_can_list_users` prolaze na obje grane.

### b) Ponovljeni napad

PUT iz koraka 4 sada vraća `{"userId":2,"displayName":"Marko","email":"m@x.hr","role":"USER"}` — `role` je
ignoriran. `GET /api/lab02/admin/users` ponovno vraća **403**. Dodatno, neispravan unos (prazan `displayName`,
`email` koji nije e-pošta, nedostajuća polja) sada daje **400** `{"error":"Neispravan zahtjev.","fields":[...]}`.

### c) Ponovno skeniranje

Mass assignment je logička ranjivost koju Bandit/Ruff u pravilu **ne** prijavljuju (nema „opasnog“ poziva,
nego preširok model). Otkriva se *code reviewom* (traži se `role`/`is_admin` u ulaznom modelu) i dinamičkim
testom (ubacivanje neočekivanog polja) u Burpu ili **OWASP ZAP**-u. Jedinični test je glavni dokaz popravka.

## 8. Zadatak za samostalni rad

- Dodajte administratorski endpoint `PUT /api/lab02/admin/users/{user_id}/role` koji smije mijenjati ulogu
  **samo** ako je pozivatelj ADMIN i **napišite dodatni pytest test** (ADMIN uspije, USER dobije 403).

**Pitanja za razmišljanje:**
1. Koja je razlika između „allowlist“ i „denylist“ pristupa poljima DTO-a i zašto je allowlist sigurniji?
2. Koja je razlika između `extra="ignore"` i `extra="forbid"` u Pydanticu i kad biste upotrijebili koji?
3. Zašto validacija ulaza nije dovoljna bez autorizacije (i obrnuto)?
