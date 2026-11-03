"""Pokretanje naredbom ``python -m vulnshop`` (http://localhost:8000, Swagger UI na /docs)."""

import os

import uvicorn


def main() -> None:
    port = int(os.environ.get("PORT", "8000"))
    print(f"VulnShop Akademija: http://localhost:{port}  (Swagger UI: http://localhost:{port}/docs)")
    # Namjerno samo 127.0.0.1 - ranjiva aplikacija ne smije biti dostupna s mreze.
    uvicorn.run("vulnshop.main:app", host="127.0.0.1", port=port)


if __name__ == "__main__":
    main()
