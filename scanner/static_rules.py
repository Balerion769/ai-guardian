"""Diff-aware static security rules driven by source syntax trees."""

import ast
import ipaddress
import math
import textwrap
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from scanner.models import Vulnerability

try:
    from tree_sitter import Language, Node, Parser
    import tree_sitter_javascript
    import tree_sitter_typescript
except ImportError:
    Language = Node = Parser = None  # type: ignore[assignment,misc]
    tree_sitter_javascript = tree_sitter_typescript = None  # type: ignore[assignment]


@dataclass(frozen=True)
class SourceLine:
    """A reconstructed new-file line and its change marker."""

    text: str
    reference: str
    added: bool


_DETAILS = {
    "aws": ("Secret Leak", "AWS access key is present in source.", "Rotate the key; use key = os.environ['AWS_ACCESS_KEY_ID']."),
    "private": ("Secret Leak", "A private key is present in source.", "Rotate the key; use key = secret_store.get('private_key')."),
    "github": ("Secret Leak", "A GitHub token is present in source.", "Revoke it; use token = os.environ['GITHUB_TOKEN']."),
    "slack": ("Secret Leak", "A Slack token is present in source.", "Revoke it; use token = os.environ['SLACK_TOKEN']."),
    "jwt": ("Secret Leak", "A hardcoded JWT is present in source.", "Revoke it; use token = request.headers.get('Authorization')."),
    "password": ("Secret Leak", "A hardcoded password is present in source.", "Rotate it; use password = os.environ['DB_PASSWORD']."),
    "execution": ("Unsafe Code Execution", "Dynamic code execution may run untrusted input.", "Use data = json.loads(user_input) or explicit dispatch instead of eval()."),
    "sql": ("SQL Injection", "SQL query is built with string concatenation.", "Use cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))."),
    "uri": ("Cleartext Connection String", "A connection string contains embedded credentials.", "Use dsn = os.environ['DATABASE_URL'] and TLS."),
}
_CANDIDATES = (
    "akia", "asia", "private key", "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
    "github_pat_", "xox", "eyj", "password", "passwd", "pwd", "eval", "exec",
    "query", "raw(", "://", "system", "subprocess", "open(", "requests.",
    "urlopen", "template(", "render_template_string", "pickle", "yaml.load",
    "marshal", "md5", "sha1", "random", "secret_key", "jwt.encode",
    "api_key", "apikey", "cors", "debug", "verify=false", "chmod", "mktemp",
    "innerhtml", "outerhtml", "document.write", "function(", "token", "secret", "api_key", " key",
)
_SQL_VERBS = ("SELECT ", "INSERT ", "UPDATE ", "DELETE ")
_CONNECTION_SCHEMES = {"postgres", "postgresql", "mysql", "mongodb", "mongodb+srv", "redis", "amqp"}
_MAX_CANDIDATES = 128


def _finding(kind: str, reference: str) -> Vulnerability:
    """Build a finding without storing the credential value."""
    category, description, remediation = _DETAILS[kind]
    return Vulnerability(severity="HIGH", category=category, description=description,
                         line_reference=reference, remediation=remediation)


def _source_lines(content: str) -> list[SourceLine]:
    """Extract new-file hunk lines and preserve added versus context lines."""
    raw = content.splitlines()
    is_diff = any(line.startswith("diff --git ") or line.startswith("@@ ") for line in raw)
    if not is_diff:
        return [SourceLine(line, f"Line {number}", True) for number, line in enumerate(raw, 1)]
    lines: list[SourceLine] = []
    new_number = 0
    in_hunk = False
    file_name: str | None = None
    for position, line in enumerate(raw, 1):
        if line.startswith("diff --git "):
            in_hunk = False
            file_name = line.split(" b/", 1)[1] if " b/" in line else None
            continue
        if line.startswith("+++ b/"):
            file_name = line[6:]
            continue
        if line.startswith("@@ "):
            try:
                new_number = int(line.split(" +", 1)[1].split(" ", 1)[0].split(",", 1)[0])
            except (IndexError, ValueError):
                in_hunk = False
                continue
            in_hunk = True
            continue
        if not in_hunk or line.startswith("+++ ") or line.startswith("--- "):
            continue
        reference = f"{file_name}:Line {new_number}" if file_name and new_number else (f"Line {new_number}" if new_number else f"Diff line {position}")
        if line.startswith("+"):
            lines.append(SourceLine(line[1:], reference, True))
            new_number += 1
        elif line.startswith(" "):
            lines.append(SourceLine(line[1:], reference, False))
            new_number += 1
    return lines


def get_added_lines(diff_content: str) -> list[tuple[int, str]]:
    """Return changed new-file line numbers and source text from a patch or snippet."""
    result: list[tuple[int, str]] = []
    for line in _source_lines(diff_content):
        if line.added:
            number = line.reference.rsplit(" ", 1)[-1]
            if number.isdigit():
                result.append((int(number), line.text))
    return result


def _issue(category: str, description: str, fix: str, location: str, severity: str = "HIGH") -> Vulnerability:
    """Build one bounded finding with an actionable replacement example."""
    return Vulnerability(severity=severity, category=category, description=description,
                         line_reference=location, remediation=fix)


def _call_name(node: ast.AST) -> str:
    """Resolve a Python AST call target without source-string matching."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_call_name(node.value)}.{node.attr}"
    return ""


def _literal(node: ast.AST) -> str | None:
    """Get a literal string value when it is statically known."""
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _entropy(value: str) -> float:
    """Measure Shannon entropy of one literal without storing it."""
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def _dynamic(node: ast.AST) -> bool:
    """Identify f-strings and concatenations containing nonliteral values."""
    return isinstance(node, ast.JoinedStr) and any(isinstance(part, ast.FormattedValue) for part in node.values) or (
        isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)
        and any(isinstance(part, (ast.Name, ast.Call, ast.Attribute, ast.Subscript)) for part in ast.walk(node))
    )


def rule_r01_eval(node: ast.AST, location: str) -> list[Vulnerability]:
    """R01: Flag actual Python eval and exec calls."""
    if isinstance(node, ast.Call) and _call_name(node.func) in {"eval", "exec"}:
        return [_finding("execution", location)]
    return []


def rule_r02_shell(node: ast.AST, location: str) -> list[Vulnerability]:
    """R02: Find dynamic shell commands and shell=True subprocess calls."""
    if not isinstance(node, ast.Call) or not node.args:
        return []
    name = _call_name(node.func)
    shell = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords)
    if (name == "os.system" or name.startswith("subprocess.") and shell) and _dynamic(node.args[0]):
        return [_issue("Command Injection", "Dynamic shell command can execute attacker-controlled text.",
                       "Use subprocess.run(['command', validated_arg], shell=False).", location)]
    return []


def rule_r03_sql(node: ast.AST, location: str) -> list[Vulnerability]:
    """R03: Find dynamic SQL syntax passed directly to query APIs."""
    if isinstance(node, ast.Call) and _call_name(node.func).split(".")[-1] in {"execute", "executemany", "query", "raw"} and node.args:
        query = node.args[0]
        if _dynamic(query) and any(_sql_literal(part.value) for part in ast.walk(query) if isinstance(part, ast.Constant) and isinstance(part.value, str)):
            return [_finding("sql", location)]
    return []


def rule_r04_secret(node: ast.AST, location: str) -> list[Vulnerability]:
    """R04: Inspect parsed literals and password assignments for credentials."""
    findings: list[Vulnerability] = []
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        findings.extend(_finding(kind, location) for kind in _credential_kinds(node.value))
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value = _literal(node.value) if node.value else None
        if value and len(value) >= 4 and any(isinstance(target, ast.Name) and target.id.lower() in {"password", "passwd", "pwd"} for target in targets):
            findings.append(_finding("password", location))
        if value and len(value) >= 20 and _entropy(value) >= 3.5 and any(
            isinstance(target, ast.Name) and any(marker in target.id.lower() for marker in ("secret", "token", "api_key")) for target in targets
        ) and not _credential_kinds(value):
            findings.append(_issue("Secret Leak", "High-entropy credential literal is embedded in source.",
                                   "token = os.environ['TOKEN']", location))
    return findings


def rule_r05_path(node: ast.AST, location: str) -> list[Vulnerability]:
    """R05: Find direct traversal paths flowing into file open calls."""
    if isinstance(node, ast.Call) and _call_name(node.func) == "open" and node.args:
        path = node.args[0]
        if isinstance(path, ast.Call) and _call_name(path.func) == "os.path.join" and any(isinstance(arg, ast.Name) and arg.id.lower() in {"user_input", "filename", "user_path"} for arg in path.args):
            return [_issue("Path Traversal", "User-controlled path is joined and opened without containment validation.",
                           "candidate = (BASE / filename).resolve(); candidate.relative_to(BASE); open(candidate).", location)]
        if isinstance(path, ast.Constant) and isinstance(path.value, str) and "../" in path.value:
            return [_issue("Path Traversal", "Parent-directory traversal is present in an opened path.",
                           "candidate = (BASE / name).resolve(); candidate.relative_to(BASE); open(candidate).", location)]
    return []


def rule_r06_ssrf(node: ast.AST, location: str) -> list[Vulnerability]:
    """R06: Find request URLs taken directly from user input variables."""
    if isinstance(node, ast.Call) and _call_name(node.func) in {"requests.get", "requests.post", "requests.put", "requests.delete", "urllib.request.urlopen"} and node.args:
        if isinstance(node.args[0], ast.Name) and node.args[0].id.lower() in {"user_url", "url_input", "request_url", "user_input"}:
            return [_issue("SSRF", "User-controlled URL reaches an outbound HTTP request.",
                           "Validate scheme and resolved host against an allowlist before requests.get(allowed_url).", location)]
    return []


def rule_r07_ssti(node: ast.AST, location: str) -> list[Vulnerability]:
    """R07: Find directly supplied template source from user input."""
    if isinstance(node, ast.Call) and _call_name(node.func) in {"Template", "jinja2.Template", "mako.template.Template", "render_template_string"} and node.args:
        if isinstance(node.args[0], ast.Name) and node.args[0].id.lower() in {"user_input", "template_input", "user_template"}:
            return [_issue("Server-Side Template Injection", "User input is compiled as template source.",
                           "Render a fixed template and pass user input as a data variable: render_template('page.html', value=user_input).", location)]
    return []


def rule_r08_deserialization(node: ast.AST, location: str) -> list[Vulnerability]:
    """R08: Find unsafe Python object deserializers."""
    if isinstance(node, ast.Call) and _call_name(node.func) in {"pickle.loads", "pickle.load", "marshal.loads", "yaml.load"}:
        if _call_name(node.func) == "yaml.load" and any(kw.arg == "Loader" and _call_name(kw.value) == "yaml.SafeLoader" for kw in node.keywords):
            return []
        return [_issue("Insecure Deserialization", "Unsafe deserializer can construct objects from untrusted bytes.",
                       "Use json.loads(data) or yaml.safe_load(data) for untrusted input.", location)]
    return []


def rule_r09_crypto(node: ast.AST, location: str) -> list[Vulnerability]:
    """R09: Detect obsolete hashes, ciphers, and predictable secret generation."""
    if isinstance(node, ast.Call) and _call_name(node.func) in {"hashlib.md5", "hashlib.sha1", "DES.new", "ARC4.new", "RC4.new", "random.random"}:
        return [_issue("Weak Cryptography", "Weak or predictable primitive is used in security-sensitive code.",
                       "Use hashlib.sha256(data).digest(), AESGCM(key), or secrets.token_urlsafe(32), as appropriate.", location, "MEDIUM")]
    return []


def rule_r10_secret_key(node: ast.AST, location: str) -> list[Vulnerability]:
    """R10: Detect literal signing keys and JWT signing secrets."""
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if _literal(node.value) and any(
            isinstance(target, ast.Name) and target.id.upper() == "SECRET_KEY" or
            isinstance(target, ast.Subscript) and _literal(target.slice) == "SECRET_KEY"
            for target in targets
        ):
            return [_issue("Hardcoded Signing Key", "Signing key is embedded in source.",
                           "SECRET_KEY = os.environ['SECRET_KEY']", location)]
    if isinstance(node, ast.Call) and _call_name(node.func) == "jwt.encode" and len(node.args) > 1 and _literal(node.args[1]):
        return [_issue("Hardcoded Signing Key", "JWT is signed with a literal key.",
                       "jwt.encode(payload, os.environ['JWT_SIGNING_KEY'], algorithm='HS256')", location)]
    return []


def rule_r14_api_key(node: ast.AST, location: str) -> list[Vulnerability]:
    """R14: Detect literal API-key assignments, including .env-style names."""
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value = _literal(node.value) if node.value else None
        if value and len(value) >= 8 and any(isinstance(target, ast.Name) and ("api_key" in target.id.lower() or "apikey" in target.id.lower()) for target in targets):
            return [_issue("Hardcoded API Key", "API key is embedded in source.",
                           "API_KEY = os.environ['API_KEY']", location)]
    return []


def rule_r15_cors(node: ast.AST, location: str) -> list[Vulnerability]:
    """R15: Detect wildcard origins with credentialed CORS."""
    if isinstance(node, ast.Call) and "CORS" in _call_name(node.func):
        wildcard = any(kw.arg in {"allow_origins", "origins"} and any(isinstance(part, ast.Constant) and part.value == "*" for part in ast.walk(kw.value)) for kw in node.keywords)
        if wildcard:
            return [_issue("Insecure CORS", "Wildcard cross-origin access is configured.",
                           "CORSMiddleware(app, allow_origins=['https://trusted.example'], allow_credentials=True)", location, "MEDIUM")]
    return []


def rule_r16_debug(node: ast.AST, location: str) -> list[Vulnerability]:
    """R16: Detect production server calls with debug enabled."""
    if isinstance(node, ast.Call) and _call_name(node.func) in {"app.run", "uvicorn.run"} and any(kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords):
        return [_issue("Debug Mode", "Server debug mode can expose interactive diagnostics.",
                       "app.run(debug=False)", location, "MEDIUM")]
    return []


def rule_r17_ip(node: ast.AST, location: str) -> list[Vulnerability]:
    """R17: Detect fixed private IP addresses in outbound request URLs."""
    if isinstance(node, ast.Call) and _call_name(node.func).startswith("requests.") and node.args:
        value = _literal(node.args[0])
        if value and "://" in value:
            try:
                host = urlsplit(value).hostname
                if host and ipaddress.ip_address(host).is_private:
                    return [_issue("Hardcoded Internal IP", "Outbound request targets a fixed private IP address.",
                                   "requests.get(os.environ['SERVICE_URL'])", location, "LOW")]
            except ValueError:
                pass
    return []


def rule_r18_tls(node: ast.AST, location: str) -> list[Vulnerability]:
    """R18: Detect requests calls that disable certificate verification."""
    if isinstance(node, ast.Call) and _call_name(node.func).startswith("requests.") and any(kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False for kw in node.keywords):
        return [_issue("TLS Verification Disabled", "HTTPS certificate verification is disabled.",
                       "requests.get(url, verify=True)", location, "HIGH")]
    return []


def rule_r19_permissions(node: ast.AST, location: str) -> list[Vulnerability]:
    """R19: Detect world-writable filesystem permissions."""
    if isinstance(node, ast.Call) and _call_name(node.func) == "os.chmod" and len(node.args) > 1 and isinstance(node.args[1], ast.Constant) and node.args[1].value == 0o777:
        return [_issue("World-Writable Permissions", "File permissions allow every local user to write.",
                       "os.chmod(path, 0o600)", location, "MEDIUM")]
    return []


def rule_r20_temp(node: ast.AST, location: str) -> list[Vulnerability]:
    """R20: Detect predictable temporary file names."""
    if isinstance(node, ast.Call) and _call_name(node.func) == "tempfile.mktemp":
        return [_issue("Insecure Temporary File", "Predictable temporary path can enable a race or symlink attack.",
                       "with tempfile.NamedTemporaryFile(delete=False) as tmp: pass", location, "MEDIUM")]
    return []


_PYTHON_RULES = (rule_r01_eval, rule_r02_shell, rule_r03_sql, rule_r04_secret,
                 rule_r05_path, rule_r06_ssrf, rule_r07_ssti, rule_r08_deserialization,
                 rule_r09_crypto, rule_r10_secret_key, rule_r14_api_key, rule_r15_cors,
                 rule_r16_debug, rule_r17_ip, rule_r18_tls, rule_r19_permissions,
                 rule_r20_temp)


def _windows(lines: list[SourceLine]) -> tuple[list[list[SourceLine]], bool]:
    """Parse small neighborhoods around candidate lines to keep scans fast."""
    indices = [index for index, line in enumerate(lines) if line.added and any(marker in line.text.lower() for marker in _CANDIDATES)]
    if len(indices) > _MAX_CANDIDATES:
        selected = [indices[round(position * (len(indices) - 1) / (_MAX_CANDIDATES - 1))] for position in range(_MAX_CANDIDATES)]
        return [[lines[index]] for index in selected], True
    ranges: list[tuple[int, int]] = []
    for index in indices:
        start, end = max(0, index - 4), min(len(lines), index + 5)
        if ranges and start <= ranges[-1][1] and end - ranges[-1][0] <= 24:
            ranges[-1] = (ranges[-1][0], max(end, ranges[-1][1]))
        else:
            ranges.append((start, end))
    return [lines[start:end] for start, end in ranges], False


def _credential_kinds(value: str) -> list[str]:
    """Classify parsed string literals by token format and URI structure."""
    kinds: list[str] = []
    for token in value.replace("\n", " ").replace('"', " ").replace("'", " ").split():
        text = token.strip(";,)({}[]")
        if len(text) == 20 and text.startswith(("AKIA", "ASIA")) and all(char.isupper() or char.isdigit() for char in text):
            kinds.append("aws")
        if text.startswith(("ghp_", "gho_", "ghu_", "ghs_", "ghr_")) and len(text) >= 34 and text[4:].isalnum():
            kinds.append("github")
        if text.startswith("github_pat_") and len(text) >= 40 and all(char.isalnum() or char == "_" for char in text):
            kinds.append("github")
        if text.startswith(("xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-")) and len(text) >= 25 and all(char.isalnum() or char == "-" for char in text):
            kinds.append("slack")
        parts = text.split(".")
        if len(parts) == 3 and all(parts) and parts[0].startswith("eyJ") and parts[1].startswith("eyJ") and all(char.isalnum() or char in "-_" for char in text.replace(".", "")):
            kinds.append("jwt")
    if "-----BEGIN PRIVATE KEY-----" in value or "-----BEGIN RSA PRIVATE KEY-----" in value or "-----BEGIN EC PRIVATE KEY-----" in value:
        kinds.append("private")
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() in _CONNECTION_SCHEMES and parsed.username and parsed.password:
            kinds.append("uri")
    except ValueError:
        pass
    return list(dict.fromkeys(kinds))


def _sql_literal(value: str) -> bool:
    """Recognize SQL statement text inside a parsed expression."""
    return value.lstrip().upper().startswith(_SQL_VERBS)


def _python_findings(lines: list[SourceLine]) -> list[Vulnerability]:
    """Inspect Python calls, assignments, and literal values via ast."""
    source = textwrap.dedent("\n".join(line.text for line in lines))
    try:
        tree = ast.parse(source)
    except SyntaxError:
        findings: list[Vulnerability] = []
        for line in lines:
            if line.added:
                text = line.text.strip()
                if text.startswith("-----BEGIN ") and "PRIVATE KEY-----" in text:
                    findings.append(_finding("private", line.reference))
                elif text and len(lines) > 1:
                    findings.extend(_python_findings([line]))
        return findings

    findings: list[Vulnerability] = []

    def reference(node: ast.AST) -> str | None:
        """Find the first changed line intersecting a syntax node."""
        start = max(0, getattr(node, "lineno", 1) - 1)
        end = min(len(lines), getattr(node, "end_lineno", start + 1))
        return next((line.reference for line in lines[start:end] if line.added), None)

    for node in ast.walk(tree):
        location = reference(node)
        if location is None:
            continue
        for rule in _PYTHON_RULES:
            findings.extend(rule(node, location))
    return findings


def _descendants(node: Node) -> list[Node]:
    """Walk tree-sitter nodes for expression checks."""
    result = [node]
    for child in node.named_children:
        result.extend(_descendants(child))
    return result


def rule_r11_js(node: Node, node_text: Callable[[Node], str], location: str) -> list[Vulnerability]:
    """R11: Detect JavaScript eval and dynamic Function construction."""
    if node.type not in {"call_expression", "new_expression"}:
        return []
    function = node.child_by_field_name("function") or node.child_by_field_name("constructor")
    if function and node_text(function) in {"eval", "Function"}:
        return [_issue("Unsafe Code Execution", "Dynamic code execution may run untrusted input.",
                       "Use JSON.parse(data) or an explicit function dispatch table.", location)]
    return []


def rule_r12_js(node: Node, node_text: Callable[[Node], str], location: str) -> list[Vulnerability]:
    """R12: Detect dynamic HTML sinks fed by expressions."""
    if node.type == "assignment_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left and right and node_text(left).endswith((".innerHTML", ".outerHTML")) and right.type not in {"string", "template_string"}:
            return [_issue("DOM XSS", "Dynamic value is assigned to an HTML parsing sink.",
                           "element.textContent = userInput;", location)]
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function and arguments and node_text(function) == "document.write" and arguments.named_children and arguments.named_children[0].type != "string":
            return [_issue("DOM XSS", "Dynamic value is written as parsed document markup.",
                           "element.textContent = userInput;", location)]
    return []


def rule_r13_js(node: Node, node_text: Callable[[Node], str], location: str) -> list[Vulnerability]:
    """R13: Detect concatenated SQL in JavaScript query calls."""
    if node.type != "call_expression":
        return []
    function = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if not function or not arguments or not node_text(function).endswith((".query", ".execute")) or not arguments.named_children:
        return []
    query = arguments.named_children[0]
    parts = _descendants(query)
    dynamic = query.type == "binary_expression" and any(part.type in {"identifier", "call_expression", "member_expression"} for part in parts)
    dynamic = dynamic or query.type == "template_string" and any(part.type == "template_substitution" for part in parts)
    if dynamic and any(part.type in {"string", "string_fragment"} and _sql_literal(node_text(part).strip("'\"`")) for part in parts):
        return [_finding("sql", location)]
    return []


def _tree_sitter_findings(lines: list[SourceLine], language: str) -> list[Vulnerability]:
    """Inspect JavaScript or TypeScript tree-sitter nodes."""
    if Parser is None or Language is None:
        return _esprima_findings(lines, language)
    grammar = tree_sitter_javascript.language() if language == "javascript" else tree_sitter_typescript.language_typescript()
    source = "\n".join(line.text for line in lines).encode("utf-8")
    root = Parser(Language(grammar)).parse(source).root_node
    findings: list[Vulnerability] = []

    def node_text(node: Node) -> str:
        """Decode the exact text of a tree-sitter node."""
        return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    def reference(node: Node) -> str | None:
        """Find an added line intersecting a syntax node."""
        end = min(len(lines), node.end_point.row + 1)
        return next((line.reference for line in lines[node.start_point.row:end] if line.added), None)

    def visit(node: Node) -> None:
        """Check relevant nodes, ignoring comments and quoted code."""
        location = reference(node)
        if location is None:
            return
        for rule in (rule_r11_js, rule_r12_js, rule_r13_js):
            findings.extend(rule(node, node_text, location))
        if node.type == "string":
            text = node_text(node)
            findings.extend(_finding(kind, location) for kind in _credential_kinds(text[1:-1]))
        elif node.type == "template_string":
            for fragment in node.named_children:
                if fragment.type == "string_fragment":
                    findings.extend(_finding(kind, location) for kind in _credential_kinds(node_text(fragment)))
        elif node.type == "variable_declarator":
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            constant_template = value is not None and value.type == "template_string" and not any(child.type == "template_substitution" for child in value.named_children)
            literal_value = value is not None and (value.type == "string" or constant_template)
            if name and value and node_text(name).lower() in {"password", "passwd", "pwd"} and literal_value and len(node_text(value)) >= 6:
                findings.append(_finding("password", location))
        elif node.type == "call_expression":
            function = node.child_by_field_name("function")
            arguments = node.child_by_field_name("arguments")
            if function and function.type == "identifier" and node_text(function) in {"eval", "exec"}:
                findings.append(_finding("execution", location))
            if function and function.type == "member_expression" and arguments:
                prop = function.child_by_field_name("property")
                if prop and node_text(prop) in {"execute", "executemany", "query", "raw"} and arguments.named_children:
                    query = arguments.named_children[0]
                    parts = _descendants(query)
                    dynamic = query.type == "binary_expression" and any(child.type in {"identifier", "call_expression", "member_expression", "subscript_expression"} for child in parts)
                    dynamic = dynamic or (query.type == "template_string" and any(child.type == "template_substitution" for child in parts))
                    if dynamic and any(child.type in {"string", "string_fragment"} and _sql_literal(node_text(child).strip("'\"`")) for child in parts):
                        findings.append(_finding("sql", location))
        for child in node.named_children:
            visit(child)

    visit(root)
    return findings


def _esprima_findings(lines: list[SourceLine], language: str) -> list[Vulnerability]:
    """Use esprima's AST if tree-sitter cannot be imported."""
    import esprima

    try:
        tree = esprima.parseScript("\n".join(line.text for line in lines), {"loc": True, "tolerant": True}).toDict()
    except esprima.Error:
        return [Vulnerability(
            severity="HIGH", category="Analysis Incomplete",
            description=f"The {language} source could not be parsed by the available syntax parser.",
            line_reference="N/A",
            remediation="Install tree-sitter language bindings and repeat the audit.",
        )]
    findings: list[Vulnerability] = []

    def visit(node: object) -> None:
        """Walk esprima dictionaries without matching raw code text."""
        if isinstance(node, list):
            for item in node:
                visit(item)
            return
        if not isinstance(node, dict):
            return
        location = node.get("loc")
        reference = None
        if isinstance(location, dict):
            row = location["start"]["line"] - 1
            if 0 <= row < len(lines) and lines[row].added:
                reference = lines[row].reference
        kind = node.get("type")
        if reference and kind == "Literal" and isinstance(node.get("value"), str):
            findings.extend(_finding(name, reference) for name in _credential_kinds(node["value"]))
        if reference and kind == "VariableDeclarator":
            name, value = node.get("id", {}), node.get("init", {})
            if isinstance(name, dict) and isinstance(value, dict) and str(name.get("name", "")).lower() in {"password", "passwd", "pwd"} and isinstance(value.get("value"), str) and len(value["value"]) >= 4:
                findings.append(_finding("password", reference))
        if reference and kind == "AssignmentExpression":
            left, right = node.get("left"), node.get("right")
            if isinstance(left, dict) and isinstance(right, dict) and left.get("type") == "MemberExpression":
                prop = left.get("property")
                if isinstance(prop, dict) and prop.get("name") in {"innerHTML", "outerHTML"} and right.get("type") != "Literal":
                    findings.append(_issue("DOM XSS", "Dynamic value is assigned to an HTML parsing sink.", "element.textContent = userInput;", reference))
        if reference and kind == "NewExpression":
            callee = node.get("callee")
            if isinstance(callee, dict) and callee.get("name") == "Function":
                findings.append(_issue("Unsafe Code Execution", "Dynamic code execution may run untrusted input.", "Use an explicit function dispatch table.", reference))
        if reference and kind == "CallExpression":
            callee = node.get("callee", {})
            if isinstance(callee, dict) and callee.get("type") == "Identifier" and callee.get("name") in {"eval", "exec"}:
                findings.append(_finding("execution", reference))
            if isinstance(callee, dict) and callee.get("type") == "MemberExpression":
                prop = callee.get("property", {})
                arguments = node.get("arguments", [])
                obj = callee.get("object", {})
                if isinstance(obj, dict) and isinstance(prop, dict) and obj.get("name") == "document" and prop.get("name") == "write" and arguments and isinstance(arguments[0], dict) and arguments[0].get("type") != "Literal":
                    findings.append(_issue("DOM XSS", "Dynamic value is written as parsed document markup.", "element.textContent = userInput;", reference))
                if isinstance(prop, dict) and prop.get("name") in {"execute", "executemany", "query", "raw"} and arguments:
                    query = arguments[0]
                    if isinstance(query, dict) and query.get("type") == "BinaryExpression" and query.get("operator") == "+":
                        stack = [query]
                        parts: list[dict[str, object]] = []
                        while stack:
                            current = stack.pop()
                            parts.append(current)
                            stack.extend(value for value in current.values() if isinstance(value, dict))
                        has_sql = any(part.get("type") == "Literal" and isinstance(part.get("value"), str) and _sql_literal(part["value"]) for part in parts)
                        has_dynamic = any(part.get("type") in {"Identifier", "CallExpression", "MemberExpression"} for part in parts)
                        if has_sql and has_dynamic:
                            findings.append(_finding("sql", reference))
        for value in node.values():
            if isinstance(value, (dict, list)):
                visit(value)

    visit(tree)
    return findings


class StaticAnalyzer:
    """Scan introduced code using AST nodes and literal-format checks."""

    def analyze(self, diff_content: str, language: str) -> list[Vulnerability]:
        """Return distinct findings from changed lines of a diff or snippet."""
        normalized = language.strip().lower()
        lines = _source_lines(diff_content)
        findings: list[Vulnerability] = []
        if normalized in {"env", "dotenv"}:
            for line in lines:
                if not line.added or "=" not in line.text or line.text.lstrip().startswith("#"):
                    continue
                key, value = line.text.split("=", 1)
                key = key.strip().lower()
                value = value.strip().strip("'\"")
                if any(marker in key for marker in ("api_key", "apikey", "secret", "password", "token")) and len(value) >= 8 and not value.startswith(("${", "$", "<")):
                    findings.append(_issue("Hardcoded API Key", "Credential value is embedded in an environment assignment.",
                                           "API_KEY=${API_KEY_FROM_SECRET_STORE}", line.reference))
            return findings
        windows, truncated = _windows(lines)
        for window in windows:
            if normalized in {"python", "py"}:
                findings.extend(_python_findings(window))
            elif normalized in {"javascript", "js", "typescript", "ts"}:
                target = "typescript" if normalized in {"typescript", "ts"} else "javascript"
                findings.extend(_tree_sitter_findings(window, target))
        if truncated and normalized in {"python", "py", "javascript", "js", "typescript", "ts"}:
            findings.append(Vulnerability(
                severity="HIGH", category="Analysis Incomplete",
                description="Static analysis sampled a dense change and could not inspect every candidate line.",
                line_reference="N/A",
                remediation="Split the change into smaller audits and review every result.",
            ))
        distinct = {(item.category, item.description, item.line_reference): item for item in findings}
        return list(distinct.values())
