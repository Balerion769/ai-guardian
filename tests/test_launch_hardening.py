"""Regression checks for patch location and versioned schema deployment."""

from pathlib import Path
from unittest.mock import patch

from alembic import command
from alembic.config import Config
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect

from dashboard.db.models import Base
from scanner.models import Vulnerability
from scanner.remediation import unified_remediation


def test_remediation_uses_file_qualified_line() -> None:
    """Same-number lines from other patch files cannot enter a suggested fix."""
    source = "diff --git a/one.py b/one.py\n@@ -0,0 +1 @@\n+eval(first)\ndiff --git a/two.py b/two.py\n@@ -0,0 +1 @@\n+eval(second)\n"
    finding = Vulnerability(severity="HIGH", category="Unsafe Code Execution", description="Dynamic call",
                            line_reference="two.py:Line 1", remediation="Use a literal parser")
    result = unified_remediation(source, "python", finding)
    assert "--- a/two.py" in result
    assert "-eval(second)" in result
    assert "+__import__('ast').literal_eval(second)" in result
    assert "first" not in result


def test_unverified_remediation_is_review_artifact() -> None:
    """Untrusted model guidance never becomes executable source automatically."""
    finding = Vulnerability(severity="HIGH", category="Unknown", description="Review issue",
                            line_reference="Line 1", remediation="run_untrusted_code()")
    result = unified_remediation("value = 1", "python", finding)
    assert result.startswith("--- /dev/null\n+++ b/AI_GUARDIAN_REVIEW.txt\n")
    assert "Review required" in result


def test_initial_migration_matches_models_and_can_roll_back(tmp_path: Path) -> None:
    """Migrate an empty database, compare every model, and undo the revision."""
    database = tmp_path / "schema.db"
    url = f"sqlite:///{database.as_posix()}"
    config = Config("alembic.ini")
    with patch.dict("os.environ", {"DATABASE_URL": url, "MIGRATION_DATABASE_URL": ""}):
        command.upgrade(config, "head")
        engine = create_engine(url)
        with engine.connect() as connection:
            assert set(Base.metadata.tables).issubset(inspect(connection).get_table_names())
            assert compare_metadata(MigrationContext.configure(connection), Base.metadata) == []
        engine.dispose()
        command.downgrade(config, "base")
        engine = create_engine(url)
        assert inspect(engine).get_table_names() == ["alembic_version"]
        engine.dispose()
