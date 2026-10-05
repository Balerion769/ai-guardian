"""Apply versioned migrations and replace the process with a hosted ASGI server."""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config

logger = logging.getLogger(__name__)


def main() -> None:
    """Start one API process; migration failures stop deployment without exposing URLs."""
    logging.basicConfig(level=logging.INFO)
    root = Path(__file__).resolve().parent.parent
    os.chdir(root)
    port = os.getenv("PORT", "8000")
    if not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError("PORT must be an integer between 1 and 65535")
    if os.getenv("FREE_AUTO_MIGRATE", "1") == "1":
        try:
            command.upgrade(Config(str(root / "alembic.ini")), "head")
        except Exception as exc:
            logger.error("free_deploy_migration_failed error_type=%s", type(exc).__name__)
            raise SystemExit(1) from None
    os.execvp(sys.executable, [sys.executable, "-m", "uvicorn", "dashboard.api.main:app",
                             "--host", "0.0.0.0", "--port", port, "--workers", "1"])


if __name__ == "__main__":
    main()
