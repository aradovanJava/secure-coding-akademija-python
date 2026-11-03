"""Lab13 – pomoćni alat koji izrađuje Base64 sadržaj za POST /api/lab13/cart/import.

Pokretanje iz korijena repozitorija:

    python -m tests.lab13.payloads

Ispisuje legitimnu košaricu (2 stavke) i napadački sadržaj (``DiagnosticsTask``) koji pri
deserijalizaciji zapisuje bezopasnu marker datoteku u privremeni direktorij.
"""

import base64
import pickle
import tempfile
from pathlib import Path

from vulnshop.lab13.models import Cart, CartItem, DiagnosticsTask


def legit_cart_payload() -> str:
    cart = Cart([CartItem("Laptop", 1), CartItem("Miš", 2)])
    return base64.b64encode(pickle.dumps(cart)).decode("ascii")


def attack_payload(report_path: str, content: str = "PWNED_LAB13") -> str:
    task = DiagnosticsTask(report_path, content)
    return base64.b64encode(pickle.dumps(task)).decode("ascii")


if __name__ == "__main__":
    marker = Path(tempfile.gettempdir()) / "lab13-pwned.txt"
    print("Legitimna košarica (2 stavke):")
    print(legit_cart_payload())
    print()
    print(f"Napadački sadržaj (zapisuje {marker}):")
    print(attack_payload(str(marker)))
