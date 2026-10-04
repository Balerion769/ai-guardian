"""Process metrics and optional Sentry reporting for the hosted service."""

from __future__ import annotations

import logging
from threading import Lock

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

logger = logging.getLogger(__name__)
audit_count = Counter("aiguardian_audit_count", "Completed audits", ["status"])
audit_latency_ms = Histogram(
    "aiguardian_audit_latency_ms",
    "Audit processing latency in milliseconds",
    buckets=(50, 100, 250, 500, 1000, 2000, 5000, 10000, 30000),
)
llm_error_count = Counter("aiguardian_llm_error_count", "LLM pass outcomes", ["outcome"])
llm_error_rate = Gauge("aiguardian_llm_error_rate", "Fraction of failed LLM passes")
_llm_total = 0
_llm_errors = 0
_lock = Lock()


def record_audit(status: str, latency_ms: float) -> None:
    """Record one completed audit without labels containing source data."""
    audit_count.labels(status=status).inc()
    audit_latency_ms.observe(max(0.0, latency_ms))


def record_llm_result(failed: bool) -> None:
    """Update the process-local LLM error ratio."""
    global _llm_total, _llm_errors
    llm_error_count.labels(outcome="error" if failed else "success").inc()
    with _lock:
        _llm_total += 1
        if failed:
            _llm_errors += 1
        llm_error_rate.set(_llm_errors / _llm_total)


def metrics_payload() -> tuple[bytes, str]:
    """Return Prometheus exposition bytes and its standards-compliant type."""
    return generate_latest(), CONTENT_TYPE_LATEST


def configure_sentry(dsn: str, environment: str) -> None:
    """Enable Sentry only when explicitly configured."""
    if not dsn:
        return
    try:
        import sentry_sdk

        sentry_sdk.init(
            dsn=dsn,
            environment=environment,
            send_default_pii=False,
            traces_sample_rate=0.0,
            before_send=lambda event, hint: _scrub_event(event),
        )
        logger.info("sentry_enabled environment=%s", environment)
    except Exception as exc:
        logger.warning("sentry_initialization_failed error_type=%s", type(exc).__name__)


def _scrub_event(event: dict) -> dict:
    """Remove request headers and bodies from error payloads."""
    request = event.get("request")
    if isinstance(request, dict):
        request.pop("data", None)
        headers = request.get("headers")
        if isinstance(headers, dict):
            request["headers"] = {key: "[REDACTED]" for key in headers}
    return event
