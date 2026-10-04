"""Behavioral tests for AIGuardian's public audit flow."""

import asyncio
import hashlib
import json
import time
import unittest
from unittest.mock import patch

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
                'private_key = "-----BEGIN PRIVATE KEY-----"',
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

    def test_same_line_in_two_diff_files_remains_two_findings(self) -> None:
        """File identity prevents cross-file finding collapse."""
        patch = """diff --git a/one.py b/one.py
--- a/one.py
+++ b/one.py
@@ -0,0 +1 @@
+key = "AKIA1234567890ABCDEF"
diff --git a/two.py b/two.py
--- a/two.py
+++ b/two.py
@@ -0,0 +1 @@
+key = "AKIA1234567890ABCDEF"
"""
        findings = StaticAnalyzer().analyze(patch, "python")
        self.assertEqual(len(findings), 2)
        self.assertEqual({item.line_reference for item in findings}, {"one.py:Line 1", "two.py:Line 1"})
        self.assertEqual(len(combine_findings(findings, [])), 2)

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


class RulePairTests(unittest.TestCase):
    """Each security rule has a positive case and a false-positive guard."""

    def assert_detects(self, source: str, description: str, language: str = "python") -> None:
        """Assert that a rule reports the expected distinct issue."""
        findings = StaticAnalyzer().analyze(source, language)
        self.assertTrue(any(description in item.description for item in findings), findings)

    def assert_safe(self, source: str, language: str = "python") -> None:
        """Assert that harmless source does not produce a static finding."""
        self.assertEqual(StaticAnalyzer().analyze(source, language), [])

    def test_aws_key_vulnerable(self) -> None:
        """Catch an AWS key stored as a Python string."""
        self.assert_detects('key = "AKIA1234567890ABCDEF"', "AWS access key")

    def test_aws_key_safe(self) -> None:
        """Ignore an AWS-shaped value in a comment."""
        self.assert_safe('# example: AKIA1234567890ABCDEF')

    def test_private_key_vulnerable(self) -> None:
        """Catch a PEM header inside a string literal."""
        self.assert_detects('key = "-----BEGIN PRIVATE KEY-----"', "private key")

    def test_private_key_safe(self) -> None:
        """Ignore a PEM header in documentation comments."""
        self.assert_safe('# do not paste -----BEGIN PRIVATE KEY----- here')

    def test_github_token_vulnerable(self) -> None:
        """Catch a literal GitHub token."""
        self.assert_detects('token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"', "GitHub token")

    def test_github_token_safe(self) -> None:
        """Ignore a GitHub token example in a comment."""
        self.assert_safe('# ghp_abcdefghijklmnopqrstuvwxyz1234567890 is an example')

    def test_slack_token_vulnerable(self) -> None:
        """Catch a literal Slack token."""
        token = "xoxb-" + "1234567890" + "-1234567890-" + "abcdefghijklmnopqrstuvwx"
        self.assert_detects(f'token = "{token}"', "Slack token")

    def test_slack_token_safe(self) -> None:
        """Ignore a Slack token example in a comment."""
        token = "xoxb-" + "1234567890" + "-1234567890-" + "abcdefghijklmnopqrstuvwx"
        self.assert_safe(f"# {token}")

    def test_jwt_vulnerable(self) -> None:
        """Catch a literal JWT."""
        self.assert_detects('token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"', "hardcoded JWT")

    def test_jwt_safe(self) -> None:
        """Ignore a JWT example in a comment."""
        self.assert_safe('# eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature')

    def test_password_vulnerable(self) -> None:
        """Catch a password assigned as a literal."""
        self.assert_detects('password = "verysecret"', "hardcoded password")

    def test_password_safe(self) -> None:
        """Do not flag a password loaded at runtime."""
        self.assert_safe('password = get_secret()')

    def test_eval_vulnerable(self) -> None:
        """Catch an actual eval call."""
        self.assert_detects('eval(user_input)', "Dynamic code execution")

    def test_eval_safe(self) -> None:
        """Do not flag text that merely mentions eval."""
        self.assert_safe('message = "eval(user_input)"')

    def test_exec_vulnerable(self) -> None:
        """Catch an actual exec call."""
        self.assert_detects('exec(user_input)', "Dynamic code execution")

    def test_exec_safe(self) -> None:
        """Do not flag text that merely mentions exec."""
        self.assert_safe('message = "exec(user_input)"')

    def test_sql_concat_vulnerable(self) -> None:
        """Catch concatenated SQL passed to execute."""
        self.assert_detects('cursor.execute("SELECT * FROM users WHERE id=" + user_id)', "SQL query")

    def test_sql_concat_safe(self) -> None:
        """Accept a parameterized query."""
        self.assert_safe('cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))')

    def test_sql_literal_concat_safe(self) -> None:
        """Joining two fixed SQL strings does not introduce user input."""
        self.assert_safe('cursor.execute("SELECT * " + "FROM users")')

    def test_multiline_sql_concat_vulnerable(self) -> None:
        """A multiline execute call still exposes dynamic SQL."""
        source = "def lookup(user_id):\n    cursor.execute(\n        'SELECT * FROM users WHERE id='\n        + user_id\n    )"
        self.assert_detects(source, "SQL query")

    def test_connection_uri_vulnerable(self) -> None:
        """Catch embedded credentials in a literal connection URI."""
        self.assert_detects('dsn = "postgresql://admin:secret@db.example/app"', "connection string")

    def test_connection_uri_safe(self) -> None:
        """Accept a URI without embedded credentials."""
        self.assert_safe('dsn = "postgresql://db.example/app"')

    def test_javascript_eval_vulnerable(self) -> None:
        """Parse a JavaScript call instead of matching text."""
        self.assert_detects('eval(userInput);', "Dynamic code execution", "javascript")

    def test_javascript_eval_safe(self) -> None:
        """Ignore JavaScript code embedded in a string."""
        self.assert_safe('const message = "eval(userInput)";', "javascript")

    def test_javascript_template_secret_vulnerable(self) -> None:
        """A static template literal containing a token is still a leak."""
        self.assert_detects('const token = `ghp_abcdefghijklmnopqrstuvwxyz1234567890`;', "GitHub token", "javascript")

    def test_javascript_template_secret_safe(self) -> None:
        """A token read at runtime through interpolation is not hardcoded."""
        self.assert_safe('const token = `${process.env.GITHUB_TOKEN}`;', "javascript")

    def test_javascript_sql_concat_vulnerable(self) -> None:
        """Catch dynamic SQL built in a JavaScript query call."""
        self.assert_detects('db.query("SELECT * FROM users WHERE id=" + userId);', "SQL query", "javascript")

    def test_javascript_sql_concat_safe(self) -> None:
        """Accept a JavaScript parameterized query."""
        self.assert_safe('db.query("SELECT * FROM users WHERE id=?", [userId]);', "javascript")

    def test_javascript_sql_literal_concat_safe(self) -> None:
        """Do not flag SQL made only from JavaScript literals."""
        self.assert_safe('db.query("SELECT * " + "FROM users");', "javascript")

    def test_javascript_esprima_fallback_sql_vulnerable(self) -> None:
        """Retain SQL injection detection when tree-sitter cannot load."""
        with patch("scanner.static_rules.Parser", None):
            self.assert_detects('db.query("SELECT * FROM users WHERE id=" + userId);', "SQL query", "javascript")

    def test_javascript_esprima_fallback_sql_safe(self) -> None:
        """The fallback accepts fixed SQL string concatenation."""
        with patch("scanner.static_rules.Parser", None):
            self.assert_safe('db.query("SELECT * " + "FROM users");', "javascript")

    def test_typescript_password_vulnerable(self) -> None:
        """Parse a typed TypeScript declaration with a hardcoded password."""
        self.assert_detects('const password: string = "verysecret";', "hardcoded password", "typescript")

    def test_typescript_password_safe(self) -> None:
        """Accept a typed declaration loaded from an environment variable."""
        self.assert_safe('const password: string = process.env.DB_PASSWORD;', "typescript")

    def test_typescript_fallback_fails_closed(self) -> None:
        """Unsupported typed syntax cannot silently produce a clean audit."""
        with patch("scanner.static_rules.Parser", None):
            findings = StaticAnalyzer().analyze('const password: string = "verysecret";', "typescript")
        self.assertEqual(findings[0].category, "Analysis Incomplete")

    def test_static_scan_200k_characters_under_200ms(self) -> None:
        """Keep a large benign source scan within the requested latency budget."""
        source = ("x = 1\n" * 33_334)[:200_000]
        started = time.perf_counter()
        findings = StaticAnalyzer().analyze(source, "python")
        elapsed = time.perf_counter() - started
        self.assertEqual(findings, [])
        self.assertLess(elapsed, 0.2, f"static scan took {elapsed:.3f}s")

    def test_dense_200k_input_is_bounded_and_fails_closed(self) -> None:
        """An adversarial volume of candidates stays fast and signals truncation."""
        source = "eval(x)\n" * 25_000
        started = time.perf_counter()
        findings = StaticAnalyzer().analyze(source, "python")
        elapsed = time.perf_counter() - started
        self.assertLess(elapsed, 0.2, f"dense scan took {elapsed:.3f}s")
        self.assertLessEqual(len(findings), 129)
        self.assertTrue(any(item.category == "Analysis Incomplete" for item in findings))


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
                json={"response": '```json\n[{"severity":"LOW","category":"Other","description":"Issue","line_reference":"Line 1","remediation":"Fix","confidence":0.9}]\n```'},
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
        attempts = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            return httpx.Response(200, json={"response": "not json"})

        async def run() -> list[Vulnerability]:
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await AIAuditor(client=client).analyze("+safe()", "python")

        findings = asyncio.run(run())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "Analysis Incomplete")
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(attempts, 4)

    def test_repairs_invalid_output_on_fourth_attempt(self) -> None:
        """Three repair prompts follow the first malformed response."""
        prompts: list[str] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            payload = json.loads(request.content)
            prompts.append(payload["prompt"])
            response = "broken" if len(prompts) < 4 else "[]"
            return httpx.Response(200, json={"response": response})

        async def run() -> list[Vulnerability]:
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await AIAuditor(client=client).analyze("x = 1", "python")

        self.assertEqual(asyncio.run(run()), [])
        self.assertEqual(len(prompts), 4)
        self.assertTrue(all("repair" in prompt.lower() for prompt in prompts[1:]))

    def test_rejects_invalid_vulnerability_schema_on_every_attempt(self) -> None:
        """Valid JSON with an invalid severity never escapes Pydantic."""
        attempts = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            return httpx.Response(200, json={"response": '[{"severity":"CRITICAL","category":"X","description":"X","line_reference":"1","remediation":"X"}]'})

        async def run() -> list[Vulnerability]:
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await AIAuditor(client=client).analyze("x = 1", "python")

        findings = asyncio.run(run())
        self.assertEqual(attempts, 4)
        self.assertEqual(findings[0].category, "Analysis Incomplete")

    def test_semantic_stage_enforces_short_deadline(self) -> None:
        """A slow model call cannot hold the API past its configured budget."""
        async def handler(request: httpx.Request) -> httpx.Response:
            await asyncio.sleep(0.2)
            return httpx.Response(200, json={"response": "[]"})

        async def run() -> None:
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                with self.assertRaises(httpx.TimeoutException):
                    await AIAuditor(timeout_seconds=0.02, client=client).analyze("x = 1", "python")

        asyncio.run(run())

    def test_invalid_output_logs_hash_not_source(self) -> None:
        """Diagnostics identify an audit without exposing the submitted code."""
        source = 'password = "never-log-this-value"'

        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"response": source})

        async def run() -> list[Vulnerability]:
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await AIAuditor(client=client).analyze(source, "python")

        with self.assertLogs("scanner.ai_auditor", level="WARNING") as captured:
            asyncio.run(run())
        combined = "\n".join(captured.output)
        self.assertNotIn(source, combined)
        self.assertIn(hashlib.sha256(source.encode()).hexdigest(), combined)

    def test_requested_long_timeout_is_capped_at_five_seconds(self) -> None:
        """Configuration cannot weaken the five-second model deadline."""
        self.assertEqual(AIAuditor(timeout_seconds=180).timeout_seconds, 5.0)

    def test_confidence_filter_and_model_deduplication(self) -> None:
        """Low-confidence guesses are dropped and higher-severity duplicates win."""
        candidates = [
            {"severity": "LOW", "category": "SQL Injection", "description": "Weak", "line_reference": "Line 1", "remediation": "Use parameters", "confidence": 0.8},
            {"severity": "HIGH", "category": "sql injection", "description": "Strong", "line_reference": "Line 1", "remediation": "Use parameters", "confidence": 0.9},
            {"severity": "HIGH", "category": "Other", "description": "Guess", "line_reference": "Line 2", "remediation": "Review", "confidence": 0.59},
        ]

        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"response": json.dumps(candidates)})

        async def run() -> list[Vulnerability]:
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await AIAuditor(client=client).analyze("x = 1", "python")

        findings = asyncio.run(run())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")


class ApiTests(unittest.TestCase):
    """Verify response semantics and unavailable Ollama behavior."""

    def test_unreachable_ollama_uses_static_only(self) -> None:
        """A connection error returns the available static result."""
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
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "PASSED")
        self.assertIn("Ollama was unavailable", response.json()["summary"])

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

    def test_static_logging_uses_hash_and_count_only(self) -> None:
        """A high static finding never writes the submitted secret to logs."""
        from main import get_ai_auditor

        source = 'key = "AKIA1234567890ABCDEF"'

        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"response": "[]"})

        async def run() -> httpx.Response:
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                app.dependency_overrides[get_ai_auditor] = lambda: AIAuditor(client=client)
                try:
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as api:
                        return await api.post("/api/v1/audit", json={"diff_content": source, "language": "python"})
                finally:
                    app.dependency_overrides.clear()

        with self.assertLogs("main", level="WARNING") as captured:
            response = asyncio.run(run())
        self.assertEqual(response.status_code, 200)
        combined = "\n".join(captured.output)
        self.assertIn(hashlib.sha256(source.encode()).hexdigest(), combined)
        self.assertIn("count=1", combined)
        self.assertNotIn(source, combined)

    def test_timeout_uses_static_only(self) -> None:
        """A stalled Ollama request returns a static-only response."""
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
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "PASSED")
        self.assertIn("Ollama was unavailable", response.json()["summary"])

    def test_size_guard_and_observability_endpoints(self) -> None:
        """Large added-line counts fail before model work; health and metrics respond."""
        async def run() -> tuple[httpx.Response, httpx.Response, httpx.Response]:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as api:
                health = await api.get("/health")
                metrics = await api.get("/metrics")
                rejected = await api.post("/api/v1/audit", json={"diff_content": "x = 1\n" * 2001, "language": "python"})
                return health, metrics, rejected

        health, metrics, rejected = asyncio.run(run())
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json()["status"], "ok")
        self.assertIn("audits", metrics.json())
        self.assertEqual(rejected.status_code, 413)

    def test_example_path_downgrades_severity(self) -> None:
        """A finding in test fixtures has one severity step less."""
        from main import _downgrade_examples

        finding = Vulnerability(severity="HIGH", category="Example", description="Issue", line_reference="tests/demo.py:Line 1", remediation="Fix")
        self.assertEqual(_downgrade_examples([finding])[0].severity, "MEDIUM")

    def test_both_engines_failing_returns_503(self) -> None:
        """No partial result is possible when both analysis engines fail."""
        from main import get_ai_auditor

        async def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        async def run() -> httpx.Response:
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as model_client:
                app.dependency_overrides[get_ai_auditor] = lambda: AIAuditor(client=model_client)
                try:
                    with patch("main.static_analyzer.analyze", side_effect=RuntimeError("parser failed")):
                        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as api:
                            return await api.post("/api/v1/audit", json={"diff_content": "x = 1", "language": "python"})
                finally:
                    app.dependency_overrides.clear()

        response = asyncio.run(run())
        self.assertEqual(response.status_code, 503)

    def test_rate_limit_rejects_sixty_first_request(self) -> None:
        """A distinct client IP receives a 429 after its minute quota."""
        from main import get_ai_auditor

        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"response": "[]"})

        async def run() -> list[int]:
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as model_client:
                app.dependency_overrides[get_ai_auditor] = lambda: AIAuditor(client=model_client)
                try:
                    transport = httpx.ASGITransport(app=app, client=("198.51.100.99", 5000))
                    async with httpx.AsyncClient(transport=transport, base_url="http://test") as api:
                        responses = [await api.post("/api/v1/audit", json={"diff_content": "x = 1", "language": "python"}) for _ in range(61)]
                    return [response.status_code for response in responses]
                finally:
                    app.dependency_overrides.clear()

        statuses = asyncio.run(run())
        self.assertEqual(statuses[:60], [200] * 60)
        self.assertEqual(statuses[60], 429)


if __name__ == "__main__":
    unittest.main()
