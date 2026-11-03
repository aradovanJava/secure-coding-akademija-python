"""Ulazna točka za uvicorn: ``uvicorn vulnshop.main:app --reload --port 8000``."""

from vulnshop.app import create_app

app = create_app()
