"""Lab13 – A08 Software or Data Integrity Failures: nesigurna deserijalizacija (CWE-502) – ISPRAVLJENO.

POPRAVAK (format se zadržava radi kompatibilnosti s postojećim klijentima):

* ograničen ``Unpickler``: ``find_class`` dopušta SAMO klase ``Cart`` i ``CartItem``; svaka druga
  klasa ili funkcija (``DiagnosticsTask``, ``os.system``, ``builtins.eval`` ...) se odbija prije
  nego što se ijedan njezin dio koda izvrši,
* ograničenje veličine sadržaja (10 000 bajtova) i provjera tipa rezultata.

Najbolje rješenje: za podatke od klijenta UOPĆE ne koristiti ``pickle``, nego JSON s
eksplicitnim modelom (Pydantic DTO). Ako format mora ostati binaran, podatke treba i potpisati
(HMAC) kako bi poslužitelj prihvaćao samo ono što je sam izdao.
"""

import base64
import io
import pickle

from fastapi import APIRouter, Request

from vulnshop.common.http import error
from vulnshop.lab13.models import Cart, CartItem

router = APIRouter(tags=["Lab13 – Nesigurna deserijalizacija"])

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
    # POPRAVAK: prihvaća se samo košarica čije su sve stavke CartItem.
    items = getattr(cart, "items", None)
    if not isinstance(cart, Cart) or not isinstance(items, list) or not all(isinstance(i, CartItem) for i in items):
        return error(400, "Neispravan sadržaj košarice.")
    return {"status": "ok", "itemCount": len(cart.items)}
