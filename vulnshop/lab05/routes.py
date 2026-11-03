"""Lab05 – A03 Software Supply Chain Failures (CWE-1104, CWE-1395) – ISPRAVLJENO.

POPRAVAK na dvije razine:

1. Ovisnost: ``jinja2`` je u requirements.txt nadograđena na 3.1.6 (ispravljeni CVE-2024-56326,
   CVE-2024-56201, CVE-2025-27516). Ranjive verzije otkrivaju pip-audit, OSV-Scanner, Trivy i
   Dependabot.
2. Uporaba: predložak je KONSTANTA, a korisnički unos se predaje kao PODATAK (varijabla
   predloška). Jinja2 tada ime samo ispisuje i ne izvršava ``{{ ... }}`` iz unosa.
"""

from fastapi import APIRouter
from jinja2.sandbox import SandboxedEnvironment
from pydantic import BaseModel

router = APIRouter(tags=["Lab05 – Ranjiva ovisnost"])

_env = SandboxedEnvironment()
# POPRAVAK: predložak je fiksan i ne sadrži korisnički unos.
GREETING_TEMPLATE = _env.from_string("Pozdrav, {{ name }}!")


class GreetingRequest(BaseModel):
    name: str | None = None


@router.post("/api/lab05/greeting")
def greeting(body: GreetingRequest):
    # POPRAVAK: korisnički unos je podatak (varijabla), a ne dio predloška.
    return {"greeting": GREETING_TEMPLATE.render(name=body.name or "")}
