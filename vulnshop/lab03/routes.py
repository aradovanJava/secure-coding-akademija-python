"""Lab03 – A01 Broken Access Control: Server-Side Request Forgery (CWE-918) – ISPRAVLJENO.

POPRAVAK:

* dopuštene su samo sheme http i https (nema file://, ftp:// ...),
* ime hosta se razrješava i SVE dobivene adrese provjeravaju se – odbijaju se loopback
  (127.0.0.0/8, ::1), privatne (10/8, 172.16/12, 192.168/16, fc00::/7), link-local
  (169.254/16 – cloud metadata, fe80::/10), 0.0.0.0 i ostale posebne adrese,
* preusmjeravanja se NE slijede (inače bi vanjski poslužitelj mogao preusmjeriti na 127.0.0.1),
* zahtjev ima vremensko ograničenje; po želji i allowlista dopuštenih domena.

Meta napada je interni endpoint ``/internal/admin/secrets`` koji vraća tajne SAMO kad zahtjev
dolazi s loopback adrese (simulira servis dostupan samo "iznutra").
"""

import ipaddress
import socket
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Request

from vulnshop.common.auth import CurrentUserDep
from vulnshop.common.http import error

router = APIRouter(tags=["Lab03 – SSRF"])

MAX_CHARS = 2000
ALLOWED_SCHEMES = {"http", "https"}
# Po želji: allowlista domena (prazan skup = provjeravaju se samo adrese).
ALLOWED_DOMAINS: set[str] = set()


class UnsafeUrlError(ValueError):
    """URL nije dopušten (shema, host ili odredišna adresa)."""


def is_forbidden_address(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])  # bez IPv6 zone (npr. fe80::1%eth0)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 -> 127.0.0.1
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_reserved
        or ip.is_multicast
        or not ip.is_global
    )


def validate_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise UnsafeUrlError("Dopuštene su samo sheme http i https.")
    host = parts.hostname
    if not host:
        raise UnsafeUrlError("URL nema host.")
    if ALLOWED_DOMAINS and host.lower() not in ALLOWED_DOMAINS:
        raise UnsafeUrlError("Domena nije na popisu dopuštenih.")
    try:
        port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
        addresses = {info[4][0] for info in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)}
    except (OSError, ValueError) as exc:
        raise UnsafeUrlError("Host nije moguće razriješiti.") from exc
    if not addresses or any(is_forbidden_address(address) for address in addresses):
        raise UnsafeUrlError("Odredište nije dopušteno (interna ili posebna adresa).")


@router.get("/api/lab03/preview")
def preview(url: str, user: CurrentUserDep):
    # POPRAVAK: provjera sheme i odredišta PRIJE slanja zahtjeva.
    try:
        validate_url(url)
    except UnsafeUrlError as exc:
        return error(400, str(exc))
    try:
        # POPRAVAK: bez slijeđenja preusmjeravanja, uz vremensko ograničenje.
        response = httpx.get(url, follow_redirects=False, timeout=5)
    except httpx.HTTPError:
        return error(502, "Dohvat nije uspio.")
    if response.is_redirect:
        return error(400, "Preusmjeravanja nisu dopuštena.")
    return {"url": url, "content": response.text[:MAX_CHARS]}


LOOPBACK_HOSTS = {"127.0.0.1", "::1"}


@router.get("/internal/admin/secrets", tags=["Lab03 – SSRF"])
def internal_secrets(request: Request):
    """Interni servis: dostupan samo s loopback adrese (nije zaštićen tokenom)."""
    client_host = request.client.host if request.client else ""
    if client_host not in LOOPBACK_HOSTS and not client_host.startswith("127."):
        return error(403, "Dostupno samo s loopback adrese.")
    return {"dbPassword": "Sup3rTajn0!", "paymentApiKey": "sk_live_akademija_123"}
