"""Zajedničke pytest "fixture" funkcije za sve testove.

* ``client`` – TestClient nad jednom instancom aplikacije (dijeli se među svim testovima,
  kao Spring kontekst u Java verziji). Testovi zato mjere RAZLIKE (prije/poslije) i koriste
  zasebne korisnike, a ne apsolutna stanja koja drugi test može promijeniti.
* ``auth("ana")`` – zaglavlje ``Authorization: Bearer <token>`` za seed korisnika.
* ``live_server`` – stvarni uvicorn poslužitelj na slobodnom portu (potreban za SSRF vježbu,
  u kojoj poslužitelj šalje zahtjev sam sebi).
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Callable, Iterator

import pytest
import uvicorn
from fastapi import FastAPI
from fastapi.testclient import TestClient

from vulnshop.app import create_app

PASSWORDS = {"ana": "Ana123!", "marko": "Marko123!", "admin": "Admin123!"}


@pytest.fixture(scope="session")
def app() -> Iterator[FastAPI]:
    application = create_app()
    yield application
    application.state.db.close()


@pytest.fixture(scope="session")
def client(app: FastAPI) -> Iterator[TestClient]:
    # raise_server_exceptions=False: ponašanje kao stvarni poslužitelj (odgovor 500 umjesto
    # iznimke u testu) - važno za vježbe Lab04 i Lab15.
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


def _login(client, username: str) -> str:
    response = client.post("/api/auth/login", json={"username": username, "password": PASSWORDS[username]})
    assert response.status_code == 200, response.text
    return response.json()["token"]


@pytest.fixture(scope="session")
def auth(client: TestClient) -> Callable[[str], dict[str, str]]:
    """Vraća funkciju: auth("ana") -> {"Authorization": "Bearer <token>"}."""
    tokens: dict[str, str] = {}

    def _auth(username: str) -> dict[str, str]:
        if username not in tokens:
            tokens[username] = _login(client, username)
        return {"Authorization": f"Bearer {tokens[username]}"}

    return _auth


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class LiveServer:
    def __init__(self, base_url: str, port: int) -> None:
        self.base_url = base_url
        self.port = port

    def auth(self, username: str) -> dict[str, str]:
        import httpx

        response = httpx.post(
            f"{self.base_url}/api/auth/login",
            json={"username": username, "password": PASSWORDS[username]},
            timeout=10,
        )
        assert response.status_code == 200, response.text
        return {"Authorization": f"Bearer {response.json()['token']}"}


@pytest.fixture(scope="session")
def live_server() -> Iterator[LiveServer]:
    port = _free_port()
    application = create_app()
    config = uvicorn.Config(application, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("uvicorn se nije pokrenuo na vrijeme")
        time.sleep(0.05)
    yield LiveServer(f"http://127.0.0.1:{port}", port)
    server.should_exit = True
    thread.join(timeout=10)
    application.state.db.close()
