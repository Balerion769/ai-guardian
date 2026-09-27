"""FastAPI entry point for two-tier security review of code changes."""

import logging
import re

import httpx
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from scanner.ai_auditor import AIAuditor
from scanner.models import AuditRequest, AuditResponse, Vulnerability
from scanner.static_rules import StaticAnalyzer


logger = logging.getLogger(__name__)
app = FastAPI(title="AIGuardian", version="1.0.0")
static_analyzer = StaticAnalyzer()


def get_ai_auditor() -> AIAuditor:
    """Construct an auditor so callers can replace it for local testing."""
    return AIAuditor()


def calculate_risk_score(vulnerabilities: list[Vulnerability]) -> int:
    """Sum severity weights and cap the score at the response maximum."""
    weights = {"HIGH": 40, "MEDIUM": 15, "LOW": 5}
    return min(100, sum(weights[item.severity] for item in vulnerabilities))


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
        line_number = re.search(r"\b\d+\s*$", finding.line_reference)
        location = line_number.group().strip() if line_number else finding.line_reference.strip().lower()
        key = (category, location)
        previous = distinct.get(key)
        if previous is None or severity_rank[finding.severity] > severity_rank[previous.severity]:
            distinct[key] = finding
    return list(distinct.values())


@app.exception_handler(httpx.TimeoutException)
async def handle_ollama_timeout(request: Request, exc: httpx.TimeoutException) -> JSONResponse:
    """Turn Ollama timeouts into a clear service-unavailable response."""
    logger.warning("Ollama request timed out for %s: %s", request.url.path, exc)
    return JSONResponse(status_code=503, content={"detail": "Ollama timed out; verify that the local model is running and retry."})


@app.exception_handler(httpx.RequestError)
async def handle_ollama_connection_error(request: Request, exc: httpx.RequestError) -> JSONResponse:
    """Report unreachable Ollama without exposing internal exception data."""
    logger.warning("Ollama request failed for %s: %s", request.url.path, exc)
    return JSONResponse(status_code=503, content={"detail": "Ollama is unavailable; start the local server and retry the audit."})


@app.exception_handler(httpx.HTTPStatusError)
async def handle_ollama_http_error(request: Request, exc: httpx.HTTPStatusError) -> JSONResponse:
    """Map Ollama's HTTP errors to an actionable API response."""
    logger.warning("Ollama HTTP error for %s: %s", request.url.path, exc.response.status_code)
    return JSONResponse(status_code=503, content={"detail": f"Ollama returned HTTP {exc.response.status_code}; verify the model and server configuration."})


@app.post("/api/v1/audit", response_model=AuditResponse)
async def audit(request: AuditRequest, ai_auditor: AIAuditor = Depends(get_ai_auditor)) -> AuditResponse:
    """Combine deterministic and semantic findings into one risk assessment."""
    static_findings = static_analyzer.analyze(request.diff_content, request.language)
    for finding in static_findings:
        if finding.severity == "HIGH":
            logger.warning("Static finding: %s at %s", finding.category, finding.line_reference)

    ai_findings = await ai_auditor.analyze(request.diff_content, request.language)
    combined = combine_findings(static_findings, ai_findings)
    failed = any(item.severity == "HIGH" for item in combined)
    incomplete = any(item.category == "Analysis Incomplete" for item in combined)
    summary = f"Found {len(combined)} security finding(s)."
    if incomplete:
        summary += " Semantic analysis was incomplete; repeat the audit before accepting the change."
    elif not combined:
        summary = "No security vulnerabilities detected in the supplied change."

    return AuditResponse(
        status="FAILED" if failed else "PASSED",
        risk_score=calculate_risk_score(combined),
        vulnerabilities=combined,
        summary=summary,
    )
