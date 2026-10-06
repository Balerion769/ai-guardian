"""GitHub App JWT compatibility regression test."""
from dataclasses import replace
from unittest.mock import patch

from dashboard.config import get_settings
from dashboard.github_app import app_jwt


def test_app_jwt_uses_string_issuer(monkeypatch) -> None:
    """PyJWT requires string issuers even for numeric GitHub App IDs."""
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setenv("DASHBOARD_DEV_MODE", "1")
    monkeypatch.setenv("DASHBOARD_SESSION_SECRET", "test-secret-with-at-least-forty-characters-long")
    settings = replace(get_settings(), github_app_id="5196548", github_app_private_key="test-key")
    with patch("dashboard.github_app.jwt.encode", return_value="signed-token") as encode:
        assert app_jwt(settings) == "signed-token"
    assert encode.call_args.args[0]["iss"] == "5196548"
