"""Lab09 – A05 Injection: OS command injection (CWE-78).

RANJIVO: endpoint sastavlja naredbu ljuske (``ping -c 1 <host>`` ili na Windowsu
``ping -n 1 <host>``) i pokreće je sa ``shell=True``, a korisnički unos ubacuje bez provjere.
Napadač može nadovezati vlastite naredbe: ``127.0.0.1 & whoami``, ``127.0.0.1; cat /etc/passwd``.
"""

import platform
import subprocess

from fastapi import APIRouter

from vulnshop.common.http import error

router = APIRouter(tags=["Lab09 – Command injection"])


@router.get("/api/lab09/ping")
def ping(host: str):
    count_flag = "-n" if platform.system() == "Windows" else "-c"
    command = f"ping {count_flag} 1 {host}"
    try:
        # RANJIVO: shell=True + korisnički unos u naredbenom retku (cmd.exe ili /bin/sh).
        result = subprocess.run(command, shell=True, capture_output=True, text=True, errors="replace", timeout=10)
    except subprocess.TimeoutExpired:
        return error(504, "Naredba je istekla.")
    except OSError:
        return error(500, "Izvršavanje nije uspjelo.")
    return {"host": host, "output": result.stdout + result.stderr}
