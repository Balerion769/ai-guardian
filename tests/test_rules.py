"""Positive and false-positive cases for the twenty static rule families."""

import unittest
from unittest.mock import patch

from scanner.static_rules import StaticAnalyzer, get_added_lines


CASES = (
    ("R01", "eval(user_input)", 'message = "eval(user_input)"', "Unsafe Code Execution", "python"),
    ("R02", 'os.system(f"ls {name}")', 'subprocess.run(["ls", name], shell=False)', "Command Injection", "python"),
    ("R03", 'cursor.execute("SELECT * FROM t WHERE id=" + user_id)', 'cursor.execute("SELECT * FROM t WHERE id=?", (user_id,))', "SQL Injection", "python"),
    ("R04", 'key = "AKIA1234567890ABCDEF"', 'key = os.environ["AWS_KEY"]', "Secret Leak", "python"),
    ("R05", 'open(os.path.join(BASE, user_input))', 'open(BASE / "fixed.txt")', "Path Traversal", "python"),
    ("R06", 'requests.get(user_url)', 'requests.get("https://example.com")', "SSRF", "python"),
    ("R07", 'Template(user_template)', 'Template("Hello {{ name }}")', "Server-Side Template Injection", "python"),
    ("R08", 'pickle.loads(data)', 'json.loads(data)', "Insecure Deserialization", "python"),
    ("R09", 'hashlib.md5(data)', 'hashlib.sha256(data)', "Weak Cryptography", "python"),
    ("R10", 'SECRET_KEY = "fixed-signing-key"', 'SECRET_KEY = os.environ["SECRET_KEY"]', "Hardcoded Signing Key", "python"),
    ("R11", 'eval(userInput);', 'const message = "eval(userInput)";', "Unsafe Code Execution", "javascript"),
    ("R12", 'element.innerHTML = userInput;', 'element.textContent = userInput;', "DOM XSS", "javascript"),
    ("R13", 'db.query("SELECT * FROM t WHERE id=" + userId);', 'db.query("SELECT * FROM t WHERE id=?", [userId]);', "SQL Injection", "javascript"),
    ("R14", 'API_KEY = "fixed-api-key-value"', 'API_KEY = os.environ["API_KEY"]', "Hardcoded API Key", "python"),
    ("R15", 'CORSMiddleware(app, allow_origins=["*"], allow_credentials=True)', 'CORSMiddleware(app, allow_origins=["https://trusted.example"], allow_credentials=True)', "Insecure CORS", "python"),
    ("R16", 'app.run(debug=True)', 'app.run(debug=False)', "Debug Mode", "python"),
    ("R17", 'requests.get("http://10.0.0.7/path")', 'requests.get("https://example.com/path")', "Hardcoded Internal IP", "python"),
    ("R18", 'requests.get(url, verify=False)', 'requests.get(url, verify=True)', "TLS Verification Disabled", "python"),
    ("R19", 'os.chmod(path, 0o777)', 'os.chmod(path, 0o600)', "World-Writable Permissions", "python"),
    ("R20", 'tempfile.mktemp()', 'tempfile.NamedTemporaryFile()', "Insecure Temporary File", "python"),
)


class StaticRuleTests(unittest.TestCase):
    """Keep each static rule paired with one benign counterpart."""


def _make_case(source: str, category: str, language: str, positive: bool):
    """Create an independently reported unittest method for one fixture."""
    def check(self: StaticRuleTests) -> None:
        findings = StaticAnalyzer().analyze(source, language)
        if positive:
            self.assertTrue(any(f.category == category for f in findings), findings)
            self.assertTrue(any("(" in f.remediation or "=" in f.remediation for f in findings if f.category == category))
        else:
            self.assertEqual(findings, [])
    return check


for rule_id, vulnerable, safe, category, language in CASES:
    setattr(StaticRuleTests, f"test_{rule_id.lower()}_vulnerable", _make_case(vulnerable, category, language, True))
    setattr(StaticRuleTests, f"test_{rule_id.lower()}_safe", _make_case(safe, category, language, False))


class DiffTests(unittest.TestCase):
    """Validate the public added-line helper."""

    def test_added_lines_ignores_removed_and_context(self) -> None:
        """Return only new line text and new-file numbers."""
        patch = "@@ -4,2 +4,2 @@\n-old()\n context()\n+eval(value)\n"
        self.assertEqual(get_added_lines(patch), [(5, "eval(value)")])

    def test_dynamic_function_constructor(self) -> None:
        """JavaScript Function construction is treated as code execution."""
        findings = StaticAnalyzer().analyze('new Function("return userInput");', "javascript")
        self.assertTrue(any(item.category == "Unsafe Code Execution" for item in findings), findings)

    def test_document_write_dynamic(self) -> None:
        """A dynamic DOM write is treated as HTML injection."""
        findings = StaticAnalyzer().analyze("document.write(userInput);", "javascript")
        self.assertTrue(any(item.category == "DOM XSS" for item in findings), findings)

    def test_dotenv_literal_key_and_reference(self) -> None:
        """Dotenv literals are found while secret-manager placeholders are accepted."""
        scanner = StaticAnalyzer()
        self.assertTrue(any(item.category == "Hardcoded API Key" for item in scanner.analyze("API_KEY=abcdefgh123456", "env")))
        self.assertEqual(scanner.analyze("API_KEY=${API_KEY_FROM_SECRET_STORE}", "env"), [])

    def test_benchmark_mode_does_not_sample_candidates(self) -> None:
        """Benchmark mode scans every suspicious line instead of capping at 128."""
        source = "\n".join(f"eval(value_{index})" for index in range(140))
        with patch.dict("os.environ", {"BENCHMARK_MODE": "1"}):
            findings = StaticAnalyzer().analyze(source, "python")
        self.assertEqual(sum(item.category == "Unsafe Code Execution" for item in findings), 140)
        self.assertFalse(any(item.category == "Analysis Incomplete" for item in findings))
