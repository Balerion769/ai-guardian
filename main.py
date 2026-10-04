"""FastAPI entry point for two-tier security review of code changes."""

import hashlib
import logging
import os
import time
from collections.abc import Awaitable, Callable
from threading import Lock

from fastapi import Depends, FastAPI, HTTPException, Request
from starlette.responses import Response
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from slowapi.extension import _rate_limit_exceeded_handler

from scanner.ai_auditor import AIAuditor
from scanner.models import AuditRequest, AuditResponse, Vulnerability
from scanner.pipeline import _downgrade_examples, calculate_risk_score, combine_findings
from scanner.static_rules import StaticAnalyzer
from scanner.static_rules import get_added_lines
from scanner.taint import analyze_taint


logger = logging.getLogger(__name__)
app = FastAPI(title="AIGuardian", version="1.0.0")
static_analyzer = StaticAnalyzer()
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
_metric_lock = Lock()
_metrics = {"audits": 0, "passed": 0, "failed": 0, "static_findings": 0, "ai_findings": 0, "ollama_failures": 0}


@app.middleware("http")
async def safe_request_logging(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    """Expose a header view that excludes Authorization to logging code."""
    request.state.audit_log_headers = tuple(
        (name, value) for name, value in request.scope.get("headers", ())
        if name.lower() != b"authorization"
    )
    return await call_next(request)


def get_ai_auditor() -> AIAuditor:
    """Construct an auditor so callers can replace it for local testing."""
    return AIAuditor()


@app.get("/health")
async def health() -> dict[str, str]:
    """Expose process readiness and the configured model name."""
    return {"status": "ok", "model": get_ai_auditor().model}


@app.get("/metrics")
async def metrics() -> dict[str, int]:
    """Return process-local counters without source or credential data."""
    with _metric_lock:
        return dict(_metrics)


@app.post("/api/v1/audit", response_model=AuditResponse)
@limiter.limit("60/minute")
async def audit(request: Request, payload: AuditRequest, ai_auditor: AIAuditor = Depends(get_ai_auditor)) -> AuditResponse:
    """Combine deterministic and semantic findings into one risk assessment."""
    started = time.perf_counter()
    if len(get_added_lines(payload.diff_content)) > 2000:
        raise HTTPException(status_code=413, detail="Audit input exceeds 2000 added lines; split the change.")
    digest = hashlib.sha256(payload.diff_content.encode("utf-8")).hexdigest()
    static_failed = False
    try:
        static_findings = static_analyzer.analyze(payload.diff_content, payload.language)
        static_findings.extend(analyze_taint(payload.diff_content, payload.language))
    except Exception:
        static_failed = True
        static_findings = []
        logger.warning("static_audit_failed diff_sha256=%s count=0", digest)
    logger.warning("static_audit diff_sha256=%s count=%d", digest, len(static_findings))
    ai_failed = False
    try:
        ai_findings = await ai_auditor.analyze(payload.diff_content, payload.language)
    except Exception:
        ai_failed = True
        ai_findings = []
        logger.warning("ollama_unavailable diff_sha256=%s count=0", digest)
    if static_failed and ai_failed:
        raise HTTPException(status_code=503, detail="Both static analysis and Ollama are unavailable; retry the audit.")
    combined = _downgrade_examples(combine_findings(static_findings, ai_findings))
    failed = any(item.severity == "HIGH" for item in combined)
    incomplete = any(item.category == "Analysis Incomplete" for item in combined)
    summary = f"Found {len(combined)} security finding(s)."
    if ai_failed:
        summary += " Ollama was unavailable; only static analysis completed."
    elif static_failed:
        summary += " Static analysis failed; only Ollama review completed."
    elif incomplete:
        summary += " Semantic analysis was incomplete; repeat the audit before accepting the change."
    elif not combined:
        summary = "No security vulnerabilities detected in the supplied change."

    result = AuditResponse(
        status="FAILED" if failed else "PASSED",
        risk_score=calculate_risk_score(combined),
        vulnerabilities=combined,
        summary=summary,
        static_count=len(static_findings),
        ai_count=len(ai_findings),
        latency_ms=round((time.perf_counter() - started) * 1000, 2),
        model_used=ai_auditor.model,
    )
    with _metric_lock:
        _metrics["audits"] += 1
        _metrics["passed" if result.status == "PASSED" else "failed"] += 1
        _metrics["static_findings"] += len(static_findings)
        _metrics["ai_findings"] += len(ai_findings)
        _metrics["ollama_failures"] += int(ai_failed)
    return result


# Docker's hosted process keeps the local scanner module importable while
# exposing the authenticated tenant app at the same API path.
if os.getenv("AIGUARDIAN_MODE") == "hosted":
    from dashboard.app import create_app

    app = create_app()
