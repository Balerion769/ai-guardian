"""Small, intraprocedural Python source-to-sink taint pass."""

import ast
import textwrap

from scanner.models import Vulnerability
from scanner.static_rules import _source_lines


_SINKS = {
    "eval", "exec", "os.system", "subprocess.call", "subprocess.Popen",
    "subprocess.run", "cursor.execute", "open", "requests.get",
    "requests.post", "requests.put", "requests.delete",
    "render_template_string", "yaml.load", "pickle.loads",
}


def _name(node: ast.AST) -> str:
    """Return a dotted call or attribute name without evaluating source code."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_name(node.value)}.{node.attr}"
    if isinstance(node, ast.Call):
        return _name(node.func)
    return ""


def _source(node: ast.AST) -> str | None:
    """Identify direct request, environment, CLI, and interactive input."""
    for child in ast.walk(node):
        name = _name(child)
        if name in {"input", "sys.argv", "os.environ.get"}:
            return name
        if name.startswith(("request.args", "request.form", "request.json", "request.values", "flask.request.")):
            return name.split("(", 1)[0]
    return None


def analyze_taint(diff_content: str, language: str) -> list[Vulnerability]:
    """Report added Python sink calls that receive locally tracked input.

    The pass is intentionally intraprocedural. It does not claim to prove that
    every input is exploitable or that a value passed between functions is safe.
    """
    if language.strip().lower() not in {"python", "py"}:
        return []
    lines = _source_lines(diff_content)
    if not lines or not any(token in diff_content for token in ("request", "input(", "sys.argv", "os.environ.get")):
        return []
    source = textwrap.dedent("\n".join(line.text for line in lines))
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    tainted: dict[str, str] = {}
    findings: list[Vulnerability] = []

    def origin(node: ast.AST) -> str | None:
        direct = _source(node)
        if direct:
            return direct
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in tainted:
                return tainted[child.id]
        return None

    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value_origin = origin(value) if value else None
            for target in targets:
                if isinstance(target, ast.Name):
                    if value_origin:
                        tainted[target.id] = value_origin
                    else:
                        tainted.pop(target.id, None)
        if not isinstance(node, ast.Call):
            continue
        sink = _name(node.func)
        if sink not in _SINKS:
            continue
        # A parameterized SQL query keeps tainted values out of query syntax.
        if sink == "cursor.execute" and node.args and isinstance(node.args[0], ast.Constant):
            continue
        value_origin = next((found for arg in node.args for found in [origin(arg)] if found), None)
        if not value_origin:
            continue
        row = getattr(node, "lineno", 1) - 1
        if row >= len(lines) or not lines[row].added:
            continue
        findings.append(Vulnerability(
            severity="HIGH", category="Tainted Input",
            description=f"Tainted input from {value_origin} reaches {sink}.",
            line_reference=lines[row].reference,
            remediation="Validate the input and use a sink-specific safe API; for SQL use cursor.execute('SELECT ... WHERE id = ?', (value,)).",
            tainted=True,
        ))
    return findings
