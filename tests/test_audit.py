"""Behavioral tests for AIGuardian's public audit flow."""

import asyncio
import json
import unittest

import httpx
from pydantic import ValidationError

from main import app, calculate_risk_score, combine_findings
from scanner.ai_auditor import AIAuditor
from scanner.models import AuditRequest, Vulnerability
from scanner.static_rules import StaticAnalyzer


class ModelTests(unittest.TestCase):
    """Reject invalid and surprising API data."""

    def test_request_rejects_empty_input_and_extra_fields(self) -> None:
        """Empty diffs and undeclared fields must fail validation."""
        with self.assertRaises(ValidationError):
            AuditRequest(diff_content="   ", language="python")
        with self.assertRaises(ValidationError):
            AuditRequest(diff_content="print(1)", language="python", surprise=True)


class StaticAnalyzerTests(unittest.TestCase):
    """Verify high-risk patterns and Git diff line selection."""

    def test_detects_secrets_and_unsafe_code(self) -> None:
        """The static pass detects the required classes with line references."""
        sample = "\n".join(
            [
                'key = "AKIA1234567890ABCDEF"',
                'token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"',
                'password = "verysecret"',
                'eval(user_input)',
                'cursor.execute("SELECT * FROM users WHERE id=" + user_id)',
                'dsn = "postgresql://admin:secret@db.example/app"',
                '-----BEGIN PRIVATE KEY-----',
                'jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"',
                'slack = "xoxb---------------------A"',
            ]
        )
        findings = StaticAnalyzer().analyze(sample, "python")
        categories = {finding.category for finding in findings}
        self.assertTrue(
            {
                "Secret Leak",
                "Unsafe Code Execution",
                "SQL Injection",
                "Cleartext Connection String",
            }.issubset(categories)
        )
        self.assertTrue(all(f.line_reference.startswith("Line ") for f in findings))
        self.assertGreaterEqual(sum(f.category == "Secret Leak" for f in findings), 6)

    def test_ignores_removed_and_context_lines(self) -> None:
        """Only added lines in a patch can introduce vulnerabilities."""
        patch = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,2 +1,2 @@
-eval(user_input)
 eval(other_input)
+print("safe")
"""
        self.assertEqual(StaticAnalyzer().analyze(patch, "python"), [])

    def test_risk_is_capped_and_high_fails(self) -> None:
        """Risk remains within the response contract."""
        finding = Vulnerability(
            severity="HIGH",
            category="Secret Leak",
            description="A secret was added.",
            line_reference="Line 1",
            remediation="Remove and rotate it.",
        )
        self.assertEqual(calculate_risk_score([finding] * 4), 100)

    def test_equivalent_findings_on_same_line_are_counted_once(self) -> None:
        """Static eval and AI code-injection labels describe one issue."""
        static = Vulnerability(
            severity="HIGH", category="Unsafe Code Execution", description="Unsafe eval.",
            line_reference="Line 1", remediation="Remove eval.",
        )
        ai = Vulnerability(
            severity="HIGH", category="Code Injection", description="Eval uses untrusted input.",
            line_reference="1", remediation="Use a parser.",
        )
        combined = combine_findings([static], [ai])
        self.assertEqual(len(combined), 1)
        self.assertEqual(calculate_risk_score(combined), 40)


class AIAuditorTests(unittest.TestCase):
    """Exercise Ollama protocol and malformed output handling."""

    def test_parses_fenced_json_and_sends_schema(self) -> None:
        """Ollama receives structured output instructions and fenced JSON is accepted."""
        async def handler(request: httpx.Request) -> httpx.Response:
            payload = json.loads(request.content)
            self.assertEqual(payload["stream"], False)
            self.assertEqual(payload["model"], "qwen2.5-coder")
            self.assertEqual(payload["format"]["type"], "array")
            return httpx.Response(
                200,
                json={"response": '```json\n[{"severity":"LOW","category":"Other","description":"Issue","line_reference":"Line 1","remediation":"Fix"}]\n```'},
            )

        async def run() -> list[Vulnerability]:
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await AIAuditor(client=client).analyze("+ risky()", "python")

        findings = asyncio.run(run())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")

    def test_rejects_invalid_timeout(self) -> None:
        """An unusable model timeout is rejected before making a request."""
        with self.assertRaises(ValueError):
            AIAuditor(timeout_seconds=0)

    def test_invalid_json_returns_incomplete_result(self) -> None:
        """Bad model output cannot be represented as a clean audit."""
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"response": "not json"})

        async def run() -> list[Vulnerability]:
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await AIAuditor(client=client).analyze("+safe()", "python")

        findings = asyncio.run(run())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "Analysis Incomplete")
        self.assertEqual(findings[0].severity, "HIGH")


class ApiTests(unittest.TestCase):
    """Verify response semantics and unavailable Ollama behavior."""

    def test_unreachable_ollama_returns_503(self) -> None:
        """A connection error yields a descriptive 503 response."""
        from main import get_ai_auditor

        async def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        async def run() -> httpx.Response:
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                app.dependency_overrides[get_ai_auditor] = lambda: AIAuditor(client=client)
                try:
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as api:
                        return await api.post("/api/v1/audit", json={"diff_content": "print(1)", "language": "python"})
                finally:
                    app.dependency_overrides.clear()

        response = asyncio.run(run())
        self.assertEqual(response.status_code, 503)
        self.assertIn("Ollama", response.json()["detail"])

    def test_successful_audit_combines_findings(self) -> None:
        """A static HIGH finding survives a clean AI result and fails the audit."""
        from main import get_ai_auditor

        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"response": "[]"})

        async def run() -> httpx.Response:
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                app.dependency_overrides[get_ai_auditor] = lambda: AIAuditor(client=client)
                try:
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as api:
                        return await api.post("/api/v1/audit", json={"diff_content": "eval(user_input)", "language": "python"})
                finally:
                    app.dependency_overrides.clear()

        response = asyncio.run(run())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "FAILED")
        self.assertEqual(response.json()["risk_score"], 40)
        self.assertEqual(response.json()["vulnerabilities"][0]["category"], "Unsafe Code Execution")

    def test_timeout_returns_503(self) -> None:
        """A stalled Ollama request receives a service-unavailable response."""
        from main import get_ai_auditor

        async def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("timed out", request=request)

        async def run() -> httpx.Response:
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                app.dependency_overrides[get_ai_auditor] = lambda: AIAuditor(client=client)
                try:
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as api:
                        return await api.post("/api/v1/audit", json={"diff_content": "print(1)", "language": "python"})
                finally:
                    app.dependency_overrides.clear()

        response = asyncio.run(run())
        self.assertEqual(response.status_code, 503)
        self.assertIn("timed out", response.json()["detail"])


if __name__ == "__main__":
    unittest.main()
