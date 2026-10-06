"""Authenticated local inference bridge security contracts."""
import httpx
from fastapi.testclient import TestClient

from scanner.ollama_bridge import create_bridge
from scanner.ai_auditor import AIAuditor
import pytest
import asyncio


TOKEN = "test-bridge-token-with-at-least-32-characters"


def test_bridge_blocks_unauthenticated_and_other_models() -> None:
    """Unknown callers and model overrides cannot invoke local inference."""
    with TestClient(create_bridge(token=TOKEN, model="llama3.2:latest")) as client:
        payload = {"model": "llama3.2:latest", "prompt": "hello"}
        assert client.post("/api/generate", json=payload).status_code == 401
        payload["model"] = "another-model"
        assert client.post("/api/generate", json=payload,
                           headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 403
        assert client.get("/api/tags").status_code == 404


def test_bridge_forwards_only_bounded_generation() -> None:
    """Authenticated inference reaches the fixed loopback upstream only."""
    requests = []
    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"response": "[]", "done": True})
    upstream = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    with TestClient(create_bridge(token=TOKEN, model="llama3.2:latest", upstream_client=upstream)) as client:
        response = client.post("/api/generate", json={"model": "llama3.2:latest", "prompt": "code_diff=print('hello')"},
                               headers={"Authorization": f"Bearer {TOKEN}"})
    assert response.status_code == 200
    assert response.json()["response"] == "[]"
    assert str(requests[0].url) == "http://127.0.0.1:11434/api/generate"


def test_bridge_rejects_unbounded_and_streaming_requests() -> None:
    """Streaming and oversized prompts cannot occupy the proxy indefinitely."""
    with TestClient(create_bridge(token=TOKEN, model="llama3.2:latest")) as client:
        headers = {"Authorization": f"Bearer {TOKEN}"}
        assert client.post("/api/generate", json={"model": "llama3.2:latest", "prompt": "x", "stream": True}, headers=headers).status_code == 422
        assert client.post("/api/generate", json={"model": "llama3.2:latest", "prompt": "x" * 220000}, headers=headers).status_code == 422


def test_auditor_sends_authentication_only_to_secure_endpoint() -> None:
    """The bridge credential reaches TLS inference and plaintext remote URLs fail."""
    def respond(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == f"Bearer {TOKEN}"
        return httpx.Response(200, json={"response": "[]"})
    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            auditor = AIAuditor(base_url="https://inference.example/api/generate", api_key=TOKEN, client=client)
            assert await auditor.analyze("print('hello')", "python") == []
    asyncio.run(run())
    with pytest.raises(ValueError, match="HTTPS"):
        AIAuditor(base_url="http://inference.example/api/generate", api_key=TOKEN)


@pytest.mark.parametrize("failure, status", [(httpx.ReadTimeout("timeout"), 504),
                                            (httpx.ConnectError("offline"), 502)])
def test_bridge_handles_upstream_failures(failure: httpx.HTTPError, status: int) -> None:
    """Upstream failures have bounded, generic responses without submitted code."""
    def respond(request: httpx.Request) -> httpx.Response:
        raise failure
    upstream = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    with TestClient(create_bridge(token=TOKEN, upstream_client=upstream)) as client:
        result = client.post("/api/generate", json={"model": "qwen2.5-coder", "prompt": "sensitive"},
                             headers={"Authorization": f"Bearer {TOKEN}"})
        assert result.status_code == status
        assert "sensitive" not in result.text


def test_bridge_rejects_short_credentials_and_oversized_body() -> None:
    """The factory requires a strong credential and bounds raw request allocation."""
    with pytest.raises(ValueError, match="32"):
        create_bridge(token="short")
    with TestClient(create_bridge(token=TOKEN)) as client:
        result = client.post("/api/generate", content=b"x" * 1000001)
        assert result.status_code == 413
