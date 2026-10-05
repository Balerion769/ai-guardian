"""Produce reviewable patches without treating model text as executable code."""

import ast
import difflib

from scanner.models import Vulnerability
from scanner.static_rules import _source_lines


def _python_replacement(source: str, finding: Vulnerability) -> str | None:
    """Return a precise single-line edit for a supported Python AST shape."""
    indentation = source[:len(source) - len(source.lstrip())]
    code = source.lstrip()
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return None
    if len(tree.body) != 1:
        return None
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Name) and node.func.id == "eval"]
    if finding.category in {"Unsafe Code Execution", "Code Injection"} and len(calls) == 1:
        target = calls[0].func
        raw = code.encode("utf-8")
        return indentation + (raw[:target.col_offset] + b"__import__('ast').literal_eval"
                              + raw[target.end_col_offset:]).decode("utf-8")
    statement = tree.body[0]
    if (finding.category == "Unsafe Code Execution" and isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Call) and isinstance(statement.value.func, ast.Name)
            and statement.value.func.id == "exec"):
        return indentation + 'raise RuntimeError("Replace dynamic exec with explicit dispatch")'
    if finding.category in {"Secret Leak", "Hardcoded API Key", "Hardcoded Signing Key"}:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            return None
        value = statement.value
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        if len(targets) != 1 or not isinstance(targets[0], ast.Name):
            return None
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return None
        variable = targets[0].id.upper()
        key = "AWS_ACCESS_KEY_ID" if value.value.startswith(("AKIA", "ASIA")) else variable
        replacement = f"__import__('os').environ[{key!r}]".encode("utf-8")
        raw = code.encode("utf-8")
        return indentation + (raw[:value.col_offset] + replacement + raw[value.end_col_offset:]).decode("utf-8")
    return None


def unified_remediation(content: str, language: str, finding: Vulnerability) -> str:
    """Return a precise source patch or an explicit review-note patch.

    The exact file-qualified reference is used so same-number lines in separate
    files cannot be confused. Unsupported fixes become a text review artifact;
    model-authored prose is never inserted into executable source.
    """
    matches = [item for item in _source_lines(content)
               if item.added and item.reference == finding.line_reference]
    line = matches[0] if len(matches) == 1 else None
    replacement = _python_replacement(line.text, finding) if line and language.lower() in {"python", "py"} else None
    if line and replacement is not None:
        path, separator, number = line.reference.rpartition(":Line ")
        if not separator:
            path, number = "input", line.reference.removeprefix("Line ")
        # References from the parsed patch cannot contain embedded newlines.
        return "\n".join((f"--- a/{path}", f"+++ b/{path}",
                          f"@@ -{number},1 +{number},1 @@", f"-{line.text}", f"+{replacement}", ""))
    note = f"Review required: {finding.category} at {finding.line_reference}\n{finding.remediation}\n"
    return "".join(difflib.unified_diff([], note.splitlines(keepends=True),
                                     fromfile="/dev/null", tofile="b/AI_GUARDIAN_REVIEW.txt"))
