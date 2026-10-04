"""Shared finding aggregation and scoring for local and hosted audits."""

from scanner.models import Vulnerability


def calculate_risk_score(vulnerabilities: list[Vulnerability]) -> int:
    """Sum severity weights and cap the score at the response maximum."""
    weights = {"HIGH": 40, "MEDIUM": 15, "LOW": 5}
    return min(100, sum(weights[item.severity] + (10 if item.tainted else 0) for item in vulnerabilities))


def combine_findings(
    static_findings: list[Vulnerability], ai_findings: list[Vulnerability]
) -> list[Vulnerability]:
    """Count equivalent static and semantic reports on one line once."""
    category_aliases = {
        "unsafe code execution": "code injection",
        "arbitrary code execution": "code injection",
        "hardcoded secret": "secret leak",
        "exposed credential": "secret leak",
    }
    severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
    distinct: dict[tuple[str, str], Vulnerability] = {}
    for finding in static_findings + ai_findings:
        category = finding.category.strip().lower()
        category = category_aliases.get(category, category)
        reference = finding.line_reference.strip().lower()
        final_part = reference.split()[-1]
        location = reference if ":" in reference else (final_part if final_part.isdigit() else reference)
        key = (category, location)
        previous = distinct.get(key)
        if previous is None or severity_rank[finding.severity] > severity_rank[previous.severity]:
            distinct[key] = finding
    return list(distinct.values())


def _downgrade_examples(findings: list[Vulnerability]) -> list[Vulnerability]:
    """Reduce priority one step for findings confined to example/test files."""
    downgrade = {"HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "LOW"}
    result: list[Vulnerability] = []
    for finding in findings:
        path = finding.line_reference.split(":Line ", 1)[0].replace("\\", "/").lower()
        parts = path.split("/")
        sample = len(parts) > 1 and any(part in {"test", "tests", "__tests__", "spec", "examples", "example"} for part in parts[:-1])
        sample = sample or len(parts) > 1 and (parts[-1].startswith("test_") or parts[-1].endswith(("_spec.py", ".spec.js", ".spec.ts")))
        result.append(finding.model_copy(update={"severity": downgrade[finding.severity]}) if sample else finding)
    return result
