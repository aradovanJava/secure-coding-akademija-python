"""Lab14 koristi zajedničku tablicu users i nema vlastitih podataka."""

from fastapi import FastAPI


def init(app: FastAPI) -> None:
    """Nema podataka za ovu vježbu."""
