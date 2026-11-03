"""Lab04 - vidi security_config.py i routes.py (kod vježbe), config.py (postavke) i docs/labs/lab04-*.md."""

from vulnshop.lab04.routes import router
from vulnshop.lab04.security_config import init

__all__ = ["init", "router"]
