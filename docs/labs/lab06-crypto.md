# Lab06 – Kriptografski propusti

## 1. Cilj vježbe

Pokazati dvije česte kriptografske pogreške: **(A)** slabo hashiranje lozinki (MD5 bez soli) i **(B)**
slabo šifriranje podataka (AES u načinu *ECB* s ključem zapisanim u izvornom kodu). Polaznik razbija takvu
zaštitu alatima, a zatim prelazi na Argon2id za lozinke i AES-GCM s ključem iz konfiguracije za podatke.

- **OWASP Top 10:2025:** A04 – Cryptographic Failures
- **CWE:** CWE-916 (*Password Hash With Insufficient Effort*), CWE-327 (*Broken/Risky Crypto Algorithm*), CWE-321 (*Hard-coded Key*), CWE-329 (*Missing/Static IV*)

## 2. Gdje je kod

- `vulnshop/lab06/routes.py`
  - Dio A: `hash_password(password)` / `verify_password(...)`; `POST /api/lab06/register`, `POST /api/lab06/login`, `GET /api/lab06/customers/export`
  - Dio B: `encrypt_card(card_number)`; `POST /api/lab06/cards`, `GET /api/lab06/cards`, `GET /api/lab06/cards/{id}/masked`
- Seed kupci (slabe lozinke): `vulnshop/lab06/data.py` – `ivan/123456`, `petra/password`, `luka/qwerty`, `maja/123456` (**ista lozinka kao ivan!**). Seed se hashira funkcijom `routes.hash_password`, pa se ispravkom automatski prebacuje na novi algoritam.
- Konfiguracija ključa (za popravak): `vulnshop/config.py` – `Settings.lab06_encryption_key` (okolina `LAB06_KEY`).
- Testovi: `tests/lab06/test_lab06_security.py`, `tests/lab06/test_lab06_functional.py`. Rječnik: `wordlists/top-100.txt`.

## 3. Opis ranjivosti

- **Dio A:** `register`/`login` koriste `MD5(hex, bez soli)`. MD5 je *brz* (GPU računa milijarde hasheva u sekundi) i bez soli, pa je offline razbijanje trivijalno; iste lozinke daju **isti** hash (ivan i maja). `customers/export` javno vraća dump – simulira već procurjelu bazu (iz sigurnosne kopije, SQL injekcije…). Pitanje nije kako sakriti dump, nego koliko vrijedi zaštita lozinki kad dump procuri.
- **Dio B:** brojevi kartica šifriraju se AES-om u načinu *ECB* s ključem `b"AkademijaKljuc16"` hardkodiranim u kodu. ECB je deterministički (isti ulaz → isti šifrat, poznata „ECB slika pingvina“) i nema zaštitu integriteta, a ključ iz koda znači da tko god vidi izvor (repozitorij, bivši zaposlenik) može dešifrirati sve.

## 4. Eksploatacija – korak po korak

Pokrenite aplikaciju s `python -m vulnshop` (host `http://localhost:8000`). Zahtjevi su u `http/lab06.http`; iste pozive možete izvesti i kroz **Swagger UI** na `http://localhost:8000/docs`. Na Linuxu/macOS-u umjesto `curl.exe` pišete `curl`.

1. **Dump lozinki:** `GET /api/lab06/customers/export`

   ```
   curl.exe -s http://localhost:8000/api/lab06/customers/export
   ```

   **Očekivano (ranjivo):** svi su 32-znamenkasti heksevi; `ivan` i `maja` imaju **identičan** hash (`e10adc3949ba59abbe56e057f20f883e`) → istu lozinku. Hasheve spremite u `hashes.txt` (jedan po retku) i razbijte ih — alatom CrackStation (<https://crackstation.net/>) ili lokalno:

   ```
   hashcat -m 0 hashes.txt wordlists/top-100.txt
   ```

   Rezultat u milisekundama: `123456`, `qwerty`, `password`. Provjera: `POST /api/lab06/login` s `{"username":"maja","password":"123456"}` → `200`.
2. **ECB determinizam:** dvaput pošaljite isti broj kartice:

   ```
   curl.exe -s -X POST http://localhost:8000/api/lab06/cards -H "Content-Type: application/json" -d "{\"cardNumber\":\"4111111111111111\"}"
   ```

   **Očekivano (ranjivo):** oba poziva vraćaju **isti** `ciphertext`. S ključem iz koda dešifrirajte ga u CyberChefu (*From Base64* → *AES Decrypt*; Key `AkademijaKljuc16` kao *UTF8*; Mode *ECB*) ili `openssl`-om — nakon Base64 dekodiranja (ključ je `AkademijaKljuc16`, heksadekadski `416b6164656d696a614b6c6a75633136`):

   ```
   openssl enc -d -aes-128-ecb -K 416b6164656d696a614b6c6a75633136 -in card.bin
   ```

   Dobije se `4111111111111111`.

## 5. Analiza uzroka

```python
def hash_password(password: str) -> str:
    # RANJIVO: MD5 bez soli (brz i deterministički).
    return hashlib.md5(password.encode("utf-8")).hexdigest()

def encrypt_card(card_number: str) -> str:
    # RANJIVO: AES u načinu ECB s hardkodiranim ključem (deterministički, bez IV-a/noncea).
    encryptor = Cipher(algorithms.AES(HARDCODED_KEY), modes.ECB()).encryptor()
    ...
```

Lozinka se „hashira“ brzom funkcijom bez soli, a podaci se šifriraju načinom koji skriva sadržaj, ali ne i obrasce, ključem koji je dostupan svakome tko ima izvorni kod.

## 6. Popravak

- **Dio A:** Argon2id (biblioteka `argon2-cffi`, `PasswordHasher`) — soljeno, memorijski zahtjevno, OWASP-ova prva preporuka. Alternative: `bcrypt`, `scrypt` ili `PBKDF2-HMAC-SHA256` s **≥ 600 000** iteracija. Seed se rehashira automatski jer `data.py` poziva `routes.hash_password`.
- **Dio B:** AES-GCM (autentificirano šifriranje) s nasumičnim **12-bajtnim nonceom** po zapisu; pohranite `nonce || šifrat || tag`. 256-bitni ključ dolazi iz okoline `LAB06_KEY` (Base64) preko `vulnshop/config.py`, a u produkciji iz KMS-a / Azure Key Vaulta / HashiCorp Vaulta — nikad iz koda.

<details>
<summary>Referentno rješenje (grana <code>rjesenja</code>)</summary>

```python
# Dio A: Argon2id – sol se generira za svaki hash.
_password_hasher = PasswordHasher()

def hash_password(password: str) -> str:
    return _password_hasher.hash(password)

def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False

# Dio B: AES-GCM s nasumičnim nonceom; ključ iz konfiguracije (LAB06_KEY, Base64, 32 B).
NONCE_SIZE = 12  # 96 bita

def get_card_cipher(request: Request) -> AESGCM:
    key = base64.b64decode(request.app.state.settings.lab06_encryption_key)
    return AESGCM(key)

def encrypt_card(cipher: AESGCM, card_number: str) -> str:
    nonce = os.urandom(NONCE_SIZE)
    ciphertext_and_tag = cipher.encrypt(nonce, card_number.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext_and_tag).decode("ascii")
```

</details>

## 7. Provjera popravka

### a) Testovi

```
pytest -m lab06
pytest -m "lab06 and security"
```

IDE: u PyCharmu kliknite zeleni ▶ pokraj testne funkcije (ili desni klik na `tests/lab06` → *Run 'pytest in lab06'*); u VS Codeu otvorite panel *Testing* (ikona tikvice) i pokrenite `tests/lab06`.

- **Prije popravka** padaju: `test_same_password_gives_different_hashes`, `test_hash_is_not_md5`, `test_same_card_gives_different_ciphertexts`, `test_hardcoded_key_no_longer_decrypts`.
- **Poslije popravka** svi prolaze: iste lozinke daju različite Argon2id hasheve (oblik `$argon2id$...`), šifrat je različit svaki put i stari ECB ključ ga više ne dešifrira. Funkcionalni (`test_register_and_login`, `test_seed_customer_can_log_in`, `test_masked_card`) prolaze na obje grane.

> **Pošteno upozorenje:** `test_ciphertext_contains_nonce_and_tag` **prolazi već na grani `main`**. Razlog: ECB uz PKCS7 za 16-znamenkastu karticu daje 32 B (puni blok + blok punjenja), što je > 16 + 12 = 28 B koje test traži. Jedan test dakle nije dovoljan — tek ostala četiri sigurnosna testa zajedno dokazuju razliku. (Isto vrijedi u Java i .NET verziji vježbe.)

### b) Ponovljeni napad

Export sada vraća Argon2id hasheve, različite za ivana i maju; `hashcat -m 0` ih ne prepoznaje kao MD5. Dvije iste kartice imaju različite šifrate, a CyberChef/`openssl` s ključem `AkademijaKljuc16` u ECB načinu ne daje broj kartice (prijava je primjetno sporija — to je namjerno).

### c) Ponovno skeniranje

```
bandit -c pyproject.toml -r vulnshop
ruff check vulnshop --select S
semgrep scan --config p/python
```

Na grani `main` Bandit/Ruff prijavljuju `B324`/`S324` (MD5) i `B305`/`S305` (ECB) u `lab06/routes.py`; nakon popravka tih nalaza nema.

## 8. Zadatak za samostalni rad

- Dodajte endpoint `GET /api/lab06/cards/{id}/decrypt` (samo za ADMIN) i **napišite dodatni pytest test** koji dokazuje da se isti broj kartice ispravno dešifrira iako su mu šifrati različiti, te da izmjena jednog bajta Base64 šifrata izazove `cryptography.exceptions.InvalidTag` (integritet GCM-a).

**Pitanja za razmišljanje:**
1. Zašto za lozinke želimo *sporu* funkciju (Argon2id/bcrypt/scrypt), a za provjeru integriteta datoteke *brzu* (SHA-256)?
2. Što se dogodi ako se isti nonce ponovno upotrijebi s istim ključem u AES-GCM-u i zašto je to katastrofalno?
3. Gdje biste u produkciji čuvali ključ za šifriranje kartica (KMS, HSM, Key Vault) i kako biste ga rotirali bez gubitka starih podataka?
