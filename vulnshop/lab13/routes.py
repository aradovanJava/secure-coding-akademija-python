"""Lab13 – A08 Software or Data Integrity Failures: nesigurna deserijalizacija (CWE-502).

RANJIVO: tijelo zahtjeva je Base64 zapis košarice serijalizirane modulom ``pickle``, a
poslužitelj ga deserijalizira s ``pickle.loads()`` bez ikakvog ograničenja. Napadač može poslati
``DiagnosticsTask`` (ili bilo što drugo) umjesto ``Cart`` i izvršiti kod već tijekom
deserijalizacije.
"""

import base64
import pickle

from fastapi import APIRouter, Request

from vulnshop.common.http import error
from vulnshop.lab13.models import Cart

router = APIRouter(tags=["Lab13 – Nesigurna deserijalizacija"])


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
