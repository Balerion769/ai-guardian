"""Local and mocked checks for the composite PR audit action."""

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import requests
import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "actions" / "ai-guardian" / "audit_pr.py"
SPEC = importlib.util.spec_from_file_location("ai_guardian_action", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Cannot load the GitHub Action runner")
ACTION = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ACTION
SPEC.loader.exec_module(ACTION)

DUMMY_DIFF = """diff --git a/src/example.py b/src/example.py
--- a/src/example.py
+++ b/src/example.py
@@ -0,0 +1 @@
+eval(user_input)
"""


class GitHubActionTests(unittest.TestCase):
    """Verify parsing, fallback, safe reporting, and local CLI behavior."""

    def test_split_diff_preserves_file_and_hunk(self) -> None:
        """Each Git diff file becomes one self-contained API input."""
        patches = ACTION.split_diff(DUMMY_DIFF + DUMMY_DIFF.replace("example.py", "other.py"))
        self.assertEqual([patch.path for patch in patches], ["src/example.py", "src/other.py"])
        self.assertTrue(all("@@ " in patch.diff for patch in patches))

    def test_static_only_finds_eval(self) -> None:
        """A local static scan reports an actual eval call."""
        findings, mode = ACTION.audit_patches(ACTION.split_diff(DUMMY_DIFF), "http://localhost:8000/api/v1/audit", True)
        self.assertEqual(mode, "static")
        self.assertTrue(any(item.finding.severity == "HIGH" for item in findings))

    def test_api_connection_failure_uses_static(self) -> None:
        """A refused local API call does not discard deterministic findings."""
        session = Mock()
        session.post.side_effect = requests.ConnectionError("unavailable")
        findings, mode = ACTION.audit_patches(ACTION.split_diff(DUMMY_DIFF), "http://localhost:8000/api/v1/audit", False, session=session)
        self.assertEqual(mode, "static fallback")
        self.assertTrue(any(item.finding.severity == "HIGH" for item in findings))

    def test_comment_never_contains_secret_or_raw_model_fix(self) -> None:
        """The PR table uses fixed guidance rather than model-supplied text."""
        from scanner.models import Vulnerability

        secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
        finding = Vulnerability(severity="HIGH", category="Secret Leak", description=secret,
                                line_reference="Line 8", remediation=f"Replace {secret}")
        body = ACTION.format_markdown([ACTION.ReportFinding("src/a.py", finding)], "static")
        self.assertIn("| File | Line | Severity | Category | Fix |", body)
        self.assertNotIn(secret, body)
        self.assertIn("src/a.py", body)

    def test_file_name_with_token_is_redacted(self) -> None:
        """Even a credential-shaped file name is withheld from the comment."""
        from scanner.models import Vulnerability

        secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
        finding = Vulnerability(severity="HIGH", category="Secret Leak", description="Leak",
                                line_reference="Line 1", remediation="Rotate")
        body = ACTION.format_markdown([ACTION.ReportFinding(f"src/{secret}.py", finding)], "static")
        self.assertNotIn(secret, body)

    def test_api_result_is_validated_before_use(self) -> None:
        """A complete response from the expected model supplies findings."""
        response = Mock()
        response.json.return_value = {
            "status": "FAILED", "risk_score": 40, "summary": "Found 1 security finding(s).",
            "static_count": 0, "ai_count": 1, "latency_ms": 10.0, "model_used": "qwen2.5-coder",
            "vulnerabilities": [{"severity": "HIGH", "category": "SQL Injection", "description": "Issue",
                                 "line_reference": "Line 1", "remediation": "Use parameters", "confidence": 0.9}],
        }
        session = Mock()
        session.post.return_value = response
        findings, mode = ACTION.audit_patches(ACTION.split_diff(DUMMY_DIFF), "http://localhost:8000/api/v1/audit", False, session=session)
        self.assertEqual(mode, "api")
        self.assertEqual(findings[0].finding.category, "SQL Injection")

    def test_invalid_api_schema_falls_back_to_static(self) -> None:
        """Malformed API responses cannot suppress a deterministic HIGH finding."""
        response = Mock()
        response.json.return_value = {"status": "PASSED"}
        session = Mock()
        session.post.return_value = response
        findings, mode = ACTION.audit_patches(ACTION.split_diff(DUMMY_DIFF), "http://localhost:8000/api/v1/audit", False, session=session)
        self.assertEqual(mode, "static fallback")
        self.assertTrue(any(item.finding.severity == "HIGH" for item in findings))

    def test_unsupported_code_fails_closed_in_static_mode(self) -> None:
        """A Java change cannot silently pass when no semantic API is used."""
        patch = DUMMY_DIFF.replace("example.py", "Example.java")
        findings, _ = ACTION.audit_patches(ACTION.split_diff(patch), "http://localhost:8000/api/v1/audit", True)
        self.assertEqual(findings[0].finding.category, "Analysis Incomplete")
        self.assertEqual(findings[0].finding.severity, "HIGH")

    def test_git_diff_uses_base_branch_or_previous_commit(self) -> None:
        """Git comparisons pass revisions as arguments without a shell."""
        result = SimpleNamespace(returncode=0, stdout=DUMMY_DIFF)
        with patch.object(ACTION.subprocess, "run", return_value=result) as runner:
            ACTION.get_git_diff(ROOT, "main")
            self.assertIn("origin/main...HEAD", runner.call_args.args[0])
            self.assertNotIn("shell", runner.call_args.kwargs)
            ACTION.get_git_diff(ROOT, None)
            self.assertIn("HEAD~1..HEAD", runner.call_args.args[0])

    def test_composite_and_workflow_metadata_parse(self) -> None:
        """Both published entry points and the copyable workflow are valid YAML."""
        root = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
        nested = yaml.safe_load((ROOT / ".github" / "actions" / "ai-guardian" / "action.yml").read_text(encoding="utf-8"))
        workflow = yaml.BaseLoader((ROOT / ".github" / "workflows" / "ai-guardian.yml").read_text(encoding="utf-8")).get_single_data()
        self.assertEqual(root["runs"]["using"], "composite")
        self.assertEqual(nested["runs"]["using"], "composite")
        self.assertEqual(workflow["jobs"]["audit"]["steps"][-1]["uses"], "Balerion769/ai-guardian@v1")
        self.assertIn("pull_request", workflow["on"])

    def test_comment_request_uses_issue_comments_endpoint(self) -> None:
        """A PR timeline comment is sent only to the repository issue endpoint."""
        session = Mock()
        session.post.return_value.status_code = 201
        ACTION.post_pr_comment("safe report", "test-token", "owner/repo", 42, session=session)
        args, kwargs = session.post.call_args
        self.assertEqual(args[0], "https://api.github.com/repos/owner/repo/issues/42/comments")
        self.assertEqual(kwargs["json"], {"body": "safe report"})
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer test-token")

    def test_cli_dummy_diff_generates_markdown_and_fails(self) -> None:
        """A local dry run emits the requested table and exits on HIGH."""
        with tempfile.TemporaryDirectory() as folder:
            patch = Path(folder) / "change.diff"
            patch.write_text(DUMMY_DIFF, encoding="utf-8")
            env = dict(os.environ, GITHUB_TOKEN="", GITHUB_EVENT_PATH="")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--diff-file", str(patch), "--use-static-only", "true",
                 "--fail-on-high", "true", "--dry-run"],
                cwd=ROOT, env=env, capture_output=True, text=True, check=False,
            )
            advisory = subprocess.run(
                [sys.executable, str(SCRIPT), "--diff-file", str(patch), "--use-static-only", "true",
                 "--fail-on-high", "false", "--dry-run"],
                cwd=ROOT, env=env, capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(advisory.returncode, 0, advisory.stderr)
        self.assertIn("| File | Line | Severity | Category | Fix |", result.stdout)
        self.assertIn("HIGH", result.stdout)
        self.assertNotIn("eval(user_input)", result.stdout)


if __name__ == "__main__":
    unittest.main()
