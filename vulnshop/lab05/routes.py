"""Lab05 – A03 Software Supply Chain Failures (CWE-1104, CWE-1395).

RANJIVO na dvije razine:

1. Ovisnost: ``jinja2==3.1.4`` (requirements.txt) ima poznate ranjivosti sandboxa
   (CVE-2024-56326, CVE-2024-56201, CVE-2025-27516) – napadač koji smije pisati predložak
   može pobjeći iz sandboxa i izvršiti proizvoljan Python kod. Ispravljeno u 3.1.5 / 3.1.6.
2. Uporaba: korisnički unos postaje dio PREDLOŠKA (server-side template injection, SSTI).
   Programer se oslonio na ``SandboxedEnvironment`` – ali sandbox ranjive verzije ne štiti.

Pokušajte ime ``{{ 7*7 }}`` ili ``{{ range(5)|list }}``: poslužitelj izvrši izraz.
"""

from fastapi import APIRouter
from jinja2.sandbox import SandboxedEnvironment
from pydantic import BaseModel

router = APIRouter(tags=["Lab05 – Ranjiva ovisnost"])

_env = SandboxedEnvironment()


class GreetingRequest(BaseModel):
    name: str | None = None


@router.post("/api/lab05/greeting")
def greeting(body: GreetingRequest):
    name = body.name or ""
    # RANJIVO: korisnički unos se ugrađuje u tekst predloška, pa Jinja2 izvršava {{ ... }} izraze.
    template = _env.from_string("Pozdrav, " + name + "!")
    return {"greeting": template.render()}
