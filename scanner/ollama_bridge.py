"""Token-protected generation-only bridge to loopback Ollama.

Run with uvicorn's factory option. Never expose Ollama's management API through
the tunnel: this service forwards only bounded, non-streaming generation calls.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator, Awaitable, Callable
import asyncio
import hmac
import os
from typing import Literal

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.responses import JSONResponse, Response


class GenerateRequest(BaseModel):
    """Strict subset of the Ollama request consumed by the security auditor."""
    model_config = ConfigDict(strict=True, extra="forbid")
    model: str = Field(min_length=1, max_length=120)
    prompt: str = Field(min_length=1, max_length=210000)
    system: str = Field(default="", max_length=8000)
    stream: Literal[False] = False
    format: dict | Literal["json"] = "json"
    options: dict = Field(default_factory=dict)


class GenerateResponse(BaseModel):
    """Validate model text while discarding unneeded upstream metadata."""
    model_config = ConfigDict(strict=True, extra="ignore")
    response: str = Field(max_length=100000)


def create_bridge(token: str | None = None, model: str | None = None,
                  upstream_client: httpx.AsyncClient | None = None) -> FastAPI:
    """Create a bridge with mandatory authentication and a single allowed model."""
    secret = token or os.getenv("OLLAMA_BRIDGE_TOKEN", "")
    allowed_model = model or os.getenv("OLLAMA_BRIDGE_MODEL", "qwen2.5-coder")
    if len(secret) < 32:
        raise ValueError("OLLAMA_BRIDGE_TOKEN must contain at least 32 characters")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        """Own and close the upstream connection pool, excluding injected clients."""
        app.state.upstream = upstream_client or httpx.AsyncClient(timeout=4.5, trust_env=False)
        app.state.inference_lock = asyncio.Lock()
        try:
            yield
        finally:
            if upstream_client is None:
                await app.state.upstream.aclose()

    app = FastAPI(title="AI Guardian Local Inference", lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)

    def authenticate(authorization: str | None = Header(default=None)) -> None:
        """Compare bearer tokens without exposing credentials in error messages."""
        expected = "Bearer " + secret
        if authorization is None or not hmac.compare_digest(authorization.encode(), expected.encode()):
            raise HTTPException(401, "Inference authentication required")

    @app.middleware("http")
    async def bound_body(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        """Bound raw input before JSON allocation; never log request bodies."""
        chunks: list[bytes] = []
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > 1000000:
                return JSONResponse({"detail": "Inference request too large"}, status_code=413)
            chunks.append(chunk)
        request._body = b"".join(chunks)
        return await call_next(request)

    @app.get("/health", dependencies=[Depends(authenticate)])
    async def health() -> dict[str, str]:
        """Report bridge availability only to authorized callers."""
        return {"status": "ok", "model": allowed_model}

    @app.post("/api/generate", dependencies=[Depends(authenticate)], response_model=GenerateResponse)
    async def generate(payload: GenerateRequest) -> GenerateResponse:
        """Forward to fixed loopback inference with bounded context and output."""
        if payload.model != allowed_model:
            raise HTTPException(403, "Model is not allowed")
        if app.state.inference_lock.locked():
            raise HTTPException(429, "Local inference is busy; retry later")
        body = payload.model_dump()
        body["options"] = {"temperature": 0, "num_predict": 768, "num_ctx": 8192}
        body["keep_alive"] = "30m"
        try:
            async with app.state.inference_lock:
                response = await app.state.upstream.post("http://127.0.0.1:11434/api/generate", json=body)
                response.raise_for_status()
                return GenerateResponse.model_validate(response.json())
        except httpx.TimeoutException as exc:
            raise HTTPException(504, "Local inference deadline exceeded") from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise HTTPException(502, "Local inference unavailable") from exc

    return app
