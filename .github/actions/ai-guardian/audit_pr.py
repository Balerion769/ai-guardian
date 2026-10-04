"""Audit a Git change and publish a source-safe pull request summary."""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence
from urllib.parse import urlparse

import requests
from pydantic import ValidationError


# Always import the action's trusted scanner, never modules from the PR checkout.
ACTION_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ACTION_ROOT))

from scanner.models import AuditResponse, Vulnerability  # noqa: E402
from scanner.static_rules import StaticAnalyzer, get_added_lines  # noqa: E402
from scanner.taint import analyze_taint  # noqa: E402


LOGGER = logging.getLogger("ai_guardian_action")
MAX_DIFF_CHARS = 200_000
MAX_ADDED_LINES = 2_000
MAX_REPORT_ROWS = 100
LANGUAGES = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".mjs": "javascript", ".cjs": "javascript", ".ts": "typescript",
    ".tsx": "typescript", ".java": "java", ".go": "go",
    ".rb": "ruby", ".php": "php", ".rs": "rust",
    ".cs": "csharp", ".c": "c", ".h": "c", ".cpp": "cpp",
    ".kt": "kotlin", ".swift": "swift", ".sh": "shell",
    ".sql": "sql", ".ipynb": "notebook",
}
STATIC_LANGUAGES = {"python", "javascript", "typescript", "env"}
SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
SAFE_FIXES = {
    "unsafe code execution": "Replace dynamic execution with a parser or explicit dispatch.",
    "code injection": "Replace dynamic execution with a parser or explicit dispatch.",
    "command injection": "Pass validated arguments as a list with shell disabled.",
    "sql injection": "Use a parameterized query and separate values.",
    "secret leak": "Rotate the credential and load its replacement from a secret store.",
    "hardcoded api key": "Rotate the key and load it from a secret store.",
    "hardcoded signing key": "Rotate the key and load it from a secret store.",
    "path traversal": "Resolve the path and enforce containment in an allowed directory.",
    "ssrf": "Allowlist outbound destinations and validate the resolved host.",
    "dom xss": "Write user data with textContent, not an HTML parser.",
    "insecure deserialization": "Use a data-only parser for untrusted input.",
    "tainted input": "Validate the input and use a sink-specific safe API.",
    "analysis incomplete": "Split the change or restore the configured analysis service.",
}


@dataclass(frozen=True)
class FilePatch:
    """A single changed file and its self-contained Git patch."""

    path: str
    diff: str
    language: str


@dataclass(frozen=True)
class ReportFinding:
    """A validated finding associated with its changed file."""

    file: str
    finding: Vulnerability


def _language_for(path: str) -> str:
    """Choose the syntax parser for a changed file, if one is supported."""
    filename = Path(path).name.lower()
    if filename == ".env" or filename.startswith(".env."):
        return "env"
    return LANGUAGES.get(Path(filename).suffix, "unknown")


def _path_from_header(header: str) -> str:
    """Decode a Git diff header without invoking a shell."""
    try:
        parts = shlex.split(header.strip())
    except ValueError:
        return "unknown"
    if len(parts) >= 4 and parts[0:2] == ["diff", "--git"] and parts[3].startswith("b/"):
        return parts[3][2:]
    return "unknown"


def split_diff(diff_text: str) -> list[FilePatch]:
    """Split a Git patch by file, retaining hunk metadata for line mapping."""
    sections: list[list[str]] = []
    current: list[str] = []
    for line in diff_text.splitlines(keepends=True):
        if line.startswith("diff --git "):
            if current:
                sections.append(current)
            current = [line]
        elif current:
            current.append(line)
    if current:
        sections.append(current)
    patches: list[FilePatch] = []
    for lines in sections:
        path = _path_from_header(lines[0])
        for line in lines:
            if line.startswith("+++ b/"):
                path = line[6:].strip()
                break
        content = "".join(lines)
        if path != "unknown" and get_added_lines(content):
            patches.append(FilePatch(path, content, _language_for(path)))
    return patches


def get_git_diff(repo: Path, base_ref: str | None) -> str:
    """Read the PR diff, or the latest commit when no base ref is available."""
    revision = f"origin/{base_ref}...HEAD" if base_ref else "HEAD~1..HEAD"
    command = ["git", "-C", str(repo), "diff", "--no-ext-diff", "--no-textconv", "--unified=3", revision, "--"]
    completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=60, check=False)
    if completed.returncode:
        raise RuntimeError("Git could not read the comparison range; use fetch-depth: 0 and fetch the base branch.")
    if len(completed.stdout) > 10_000_000:
        raise ValueError("Git comparison exceeds the 10 MB action limit")
    return completed.stdout


def _incomplete(reason: str) -> Vulnerability:
    """Fail closed when a changed code file cannot be inspected locally."""
    return Vulnerability(severity="HIGH", category="Analysis Incomplete", description=reason,
                         line_reference="N/A", remediation=SAFE_FIXES["analysis incomplete"])


def _dedupe(findings: Sequence[Vulnerability]) -> list[Vulnerability]:
    """Keep the highest severity for each category and line."""
    distinct: dict[tuple[str, str], Vulnerability] = {}
    for finding in findings:
        key = (finding.category.strip().lower(), finding.line_reference.strip().lower())
        previous = distinct.get(key)
        if previous is None or SEVERITY_RANK[finding.severity] > SEVERITY_RANK[previous.severity]:
            distinct[key] = finding
    return list(distinct.values())


def _static_findings(patch: FilePatch) -> list[Vulnerability]:
    """Run trusted syntax and taint analysis without executing changed code."""
    if patch.language not in STATIC_LANGUAGES:
        return [_incomplete("No local static parser supports this changed code file.")]
    try:
        scanner = StaticAnalyzer()
        findings = scanner.analyze(patch.diff, patch.language)
        findings.extend(analyze_taint(patch.diff, patch.language))
        return _dedupe(findings)
    except Exception:
        LOGGER.warning("Local static analysis failed for one file")
        return [_incomplete("Local static analysis failed for this changed code file.")]


def audit_patches(
    patches: Sequence[FilePatch], api_url: str, use_static_only: bool,
    model: str = "qwen2.5-coder", session: requests.Session | None = None,
) -> tuple[list[ReportFinding], str]:
    """Review each changed file via the API or the local static fallback."""
    client = session or requests.Session()
    mode = "static" if use_static_only else "api"
    findings: list[ReportFinding] = []
    for patch in patches:
        if patch.language == "unknown":
            continue
        if len(patch.diff) > MAX_DIFF_CHARS or len(get_added_lines(patch.diff)) > MAX_ADDED_LINES:
            selected = [_incomplete("Changed file exceeds the per-file audit size limit.")]
            mode = "static fallback" if not use_static_only else "static"
        elif use_static_only:
            selected = _static_findings(patch)
        else:
            try:
                response = client.post(api_url, json={"diff_content": patch.diff, "language": patch.language},
                                       timeout=(2, 7))
                response.raise_for_status()
                validated = AuditResponse.model_validate(response.json())
                if validated.model_used != model:
                    raise ValueError("Configured API model differs from the requested action model")
                selected = validated.vulnerabilities
                if "Ollama was unavailable" in validated.summary:
                    mode = "static fallback"
            except (requests.RequestException, ValueError, ValidationError):
                LOGGER.warning("API audit unavailable; using local static analysis for one file")
                selected = _static_findings(patch)
                mode = "static fallback"
        findings.extend(ReportFinding(patch.path, item) for item in selected)
    return findings, mode


def _safe_cell(value: str, maximum: int = 120) -> str:
    """Remove Markdown table controls and cap untrusted metadata length."""
    redacted = re.sub(r"AKIA[A-Z0-9]{16}|(?:gh[pousr]_|sk_live_)[A-Za-z0-9_]{12,}|[A-Za-z0-9_-]{32,}",
                      "[REDACTED]", value)
    collapsed = " ".join(redacted.split())[:maximum]
    return collapsed.replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def format_markdown(findings: Sequence[ReportFinding], mode: str) -> str:
    """Produce a PR table without source snippets or model-provided prose."""
    lines = ["<!-- ai-guardian -->", "## AI Guardian security audit", "",
             f"Analysis mode: {_safe_cell(mode, 30)}.", "",
             "| File | Line | Severity | Category | Fix |",
             "| --- | ---: | --- | --- | --- |"]
    for item in findings[:MAX_REPORT_ROWS]:
        category_key = item.finding.category.strip().lower()
        category = item.finding.category if category_key in SAFE_FIXES else "Security finding"
        fix = SAFE_FIXES.get(category_key, "Review the finding in the runner and replace the unsafe behavior.")
        last = item.finding.line_reference.rsplit(" ", 1)[-1]
        line = last if last.isdigit() else "—"
        lines.append(f"| {_safe_cell(item.file)} | {line} | {item.finding.severity} | "
                     f"{_safe_cell(category, 60)} | {_safe_cell(fix, 200)} |")
    if not findings:
        lines.append("| — | — | — | No findings | — |")
    if len(findings) > MAX_REPORT_ROWS:
        lines.extend(["", f"{len(findings) - MAX_REPORT_ROWS} additional findings omitted from this comment."])
    lines.extend(["", "The table omits source snippets and model-generated remediation text. Review findings before accepting a change."])
    return "\n".join(lines)


def post_pr_comment(
    body: str, token: str, repository: str, pr_number: int,
    session: requests.Session | None = None, api_base: str = "https://api.github.com",
) -> None:
    """Post the source-safe report to the PR's issue timeline."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or pr_number < 1:
        raise ValueError("Invalid GitHub repository or pull request number")
    parsed = urlparse(api_base)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("GitHub API URL must use HTTPS")
    client = session or requests.Session()
    url = f"{api_base.rstrip('/')}/repos/{repository}/issues/{pr_number}/comments"
    response = client.post(url, json={"body": body}, headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }, timeout=(3, 15))
    response.raise_for_status()


def _pr_number_from_event(path: str | None) -> int | None:
    """Extract a PR number from the runner event payload, if present."""
    if not path:
        return None
    try:
        event = json.loads(Path(path).read_text(encoding="utf-8"))
        number = event.get("pull_request", {}).get("number")
        return number if isinstance(number, int) and number > 0 else None
    except (OSError, ValueError, AttributeError):
        return None


def _boolean(value: str) -> bool:
    """Reject ambiguous Action input values instead of silently passing."""
    normalized = value.strip().lower()
    if normalized not in {"true", "false"}:
        raise argparse.ArgumentTypeError("Expected true or false")
    return normalized == "true"


def main(argv: Sequence[str] | None = None) -> int:
    """Run the audit, optionally comment on a PR, and enforce HIGH findings."""
    parser = argparse.ArgumentParser(description="Audit changed files with AI Guardian")
    parser.add_argument("--fail-on-high", type=_boolean, default=True)
    parser.add_argument("--api-url", default="http://localhost:8000/api/v1/audit")
    parser.add_argument("--use-static-only", type=_boolean, default=False)
    parser.add_argument("--model", default="qwen2.5-coder")
    parser.add_argument("--diff-file", type=Path, help="Read a saved Git patch instead of running git diff")
    parser.add_argument("--dry-run", action="store_true", help="Print the report without posting a comment")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    if urlparse(args.api_url).scheme not in {"http", "https"}:
        parser.error("--api-url must be an HTTP or HTTPS URL")
    try:
        if args.diff_file:
            if args.diff_file.stat().st_size > 10_000_000:
                raise ValueError("Diff file exceeds the 10 MB action limit")
            diff = args.diff_file.read_text(encoding="utf-8", errors="replace")
        else:
            diff = get_git_diff(Path(os.getenv("GITHUB_WORKSPACE", os.getcwd())), os.getenv("GITHUB_BASE_REF") or None)
        patches = split_diff(diff)
        with requests.Session() as client:
            findings, mode = audit_patches(patches, args.api_url, args.use_static_only, args.model, client)
            report = format_markdown(findings, mode)
            sys.stdout.write(report + "\n")
            if not args.dry_run:
                token = os.getenv("GITHUB_TOKEN", "")
                repository = os.getenv("GITHUB_REPOSITORY", "")
                pr_number = _pr_number_from_event(os.getenv("GITHUB_EVENT_PATH"))
                if token and repository and pr_number:
                    try:
                        post_pr_comment(report, token, repository, pr_number, client,
                                        os.getenv("GITHUB_API_URL", "https://api.github.com"))
                    except (requests.RequestException, ValueError):
                        LOGGER.warning("PR comment could not be posted; inspect token permissions")
    except (OSError, subprocess.TimeoutExpired, RuntimeError, ValueError) as exc:
        LOGGER.error("Audit could not complete: %s", type(exc).__name__)
        return 2
    return 1 if args.fail_on_high and any(item.finding.severity == "HIGH" for item in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
