"""Prometheus metric contract tests."""

from dashboard.observability import metrics_payload, record_audit, record_llm_result


def test_metrics_include_audit_latency_and_llm_error_rate():
    record_audit("PASSED", 12.5)
    record_llm_result(False)
    payload, content_type = metrics_payload()
    text = payload.decode()
    assert "aiguardian_audit_count" in text
    assert "aiguardian_audit_latency_ms" in text
    assert "aiguardian_llm_error_rate" in text
    assert "text/plain" in content_type
