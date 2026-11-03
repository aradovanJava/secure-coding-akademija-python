"""Lab09 – A05 Injection: OS command injection (CWE-78) – ISPRAVLJENO.

POPRAVAK:

* stroga validacija ulaza: host mora biti IP adresa ili ime hosta (``^[A-Za-z0-9.-]{1,253}$``) i
  ne smije počinjati crticom (inače bi postao opcija naredbe – argument injection, CWE-88),
* naredba se pokreće BEZ ljuske: ``subprocess.run([...], shell=False)`` s listom argumenata, pa
  znakovi ``&``, ``;``, ``|`` nemaju posebno značenje.

Još bolje: ne pokretati vanjske programe kad postoji biblioteka (npr. TCP provjera dostupnosti
preko modula ``socket`` ili paket ``icmplib``).
"""

import ipaddress
import platform
import re
import shutil
import subprocess

from fastapi import APIRouter

from vulnshop.common.http import error

router = APIRouter(tags=["Lab09 – Command injection"])

HOSTNAME_PATTERN = re.compile(r"^(?!-)[A-Za-z0-9.-]{1,253}$")


def is_valid_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return "%" not in host  # bez IPv6 "zone" sufiksa (npr. fe80::1%eth0) - on dopušta proizvoljan tekst
    except ValueError:
        return bool(HOSTNAME_PATTERN.fullmatch(host))


@router.get("/api/lab09/ping")
def ping(host: str):
    # POPRAVAK 1: stroga validacija (allowlista dopuštenih znakova).
    if not is_valid_host(host):
        return error(400, "Neispravan host.")
    ping_executable = shutil.which("ping")
    if ping_executable is None:
        return {"host": host, "output": "Naredba ping nije dostupna na ovom sustavu."}
    count_flag = "-n" if platform.system() == "Windows" else "-c"
    try:
        # POPRAVAK 2: bez ljuske – lista argumenata, host je samo jedan argument.
        # Host je validiran i nema ljuske, pa je nalaz alata S603/B603 ovdje svjesno prihvaćen.
        result = subprocess.run(  # noqa: S603  # nosec B603
            [ping_executable, count_flag, "1", host],
            shell=False,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return error(504, "Naredba je istekla.")
    except OSError:
        return error(500, "Izvršavanje nije uspjelo.")
    return {"host": host, "output": result.stdout + result.stderr}
