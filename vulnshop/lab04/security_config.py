"""Lab04 – RANJIVA sigurnosna konfiguracija aplikacije (CWE-16, CWE-209, CWE-942, CWE-693).

Ranjivosti ove vježbe su u konfiguraciji, a ne u poslovnom kodu:

* ``config.py``: ``debug=True`` po zadanom -> svaka neobrađena iznimka vraća cijeli traceback;
* ovdje: CORS dopušta BILO KOJI origin uz kolačiće/vjerodajnice (``allow_credentials=True``),
  a sigurnosna HTTP zaglavlja (X-Content-Type-Options, X-Frame-Options, CSP ...) se ne postavljaju;
* ``routes.py``: endpoint ``/api/lab04/debug/config`` otkriva cijelu konfiguraciju s tajnama.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


def init(app: FastAPI) -> None:
    # RANJIVO: refleksija bilo kojeg origina (regex ".*") uz dopuštene vjerodajnice.
    # Bilo koja zlonamjerna stranica može slati autentificirane zahtjeve i čitati odgovore.
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=".*",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    # RANJIVO: nema sigurnosnih zaglavlja ni generičkog rukovanja greškama.
