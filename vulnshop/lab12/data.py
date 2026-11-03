"""Lab12 – koristi zajedničku tablicu users; ovdje se stvara JwtService s tajnom iz konfiguracije."""

from fastapi import FastAPI

from vulnshop.lab12.jwt_service import JwtService


def init(app: FastAPI) -> None:
    app.state.lab12_jwt = JwtService(app.state.settings.lab12_jwt_secret)
