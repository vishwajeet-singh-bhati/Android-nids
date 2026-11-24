"""HTTP API of the phishing detector (Phase 6): FastAPI over the inference service.

    python -m src.api.app                               # http://127.0.0.1:8000  (docs: /docs)
    python -m src.api.app --host 0.0.0.0 --port 8000    # inside a container
    uvicorn src.api.app:create_app --factory --workers 1 # the same, with uvicorn's own options

Endpoints
  POST /predict     {"urls": [...], "input_type": "full_url" | "domain"}
                    -> {"results": [one per URL, same order], "model_version", "request_id"}
  GET  /health      the process is alive (liveness): always 200
  GET  /ready       the model is loaded and its worker runs (readiness): 200, else 503
  GET  /model-info  model version, thresholds, validation numbers, threat-intel status, limits
  GET  /metrics     counters in Prometheus' text format

Design
  * No model code here. The app calls src.inference.service.InferenceService,
    which also works without FastAPI (spec: the engine is usable on its own).
  * The model is loaded once at startup (lifespan), before any request is
    accepted. One worker thread owns it and every request goes through its
    bounded queue, so concurrent requests can neither load the model twice nor
    exhaust memory. Run ONE process (--workers 1): each extra process would
    load its own copy of the model.
  * If loading fails, the server still starts: /health says ok, while /ready,
    /model-info and /predict answer 503 with the reason (a container health
    check sees it).
  * Limits: request body (config/api.json max_body_bytes: 413 before reading),
    URLs per request (config/inference.json: 413), time per request and a full
    queue (503 + Retry-After). One invalid URL does not fail a request; it gets
    its own result with `error`.
  * Logs: one line per /predict call (request id, counts, time). URLs are not
    logged, except PHISHING verdicts, and those only redacted (src.utils.redact).
    422 answers do not echo the submitted input.
  * Network: none, unless SAFE_BROWSING_API_KEY is set. Then Google lookups run
    in the background, and answers list them in `pending` until they are done.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import re
import time
import uuid
from collections import Counter
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.middleware.body_limit import RequestBodyLimitMiddleware

from src.inference.predict import INPUT_TYPES
from src.inference.service import InferenceService, Overloaded, QueueTimeout, ServiceClosed
from src.preprocessing.url_normalizer import MAX_RAW_LENGTH
from src.utils.redact import redact_url

from .config import CONFIG_PATH, ApiConfig
from .metrics import CONTENT_TYPE, Metrics
from .schemas import (ErrorResponse, HealthResponse, PredictionItem, PredictRequest, PredictResponse,
                      ReadyResponse)

API_VERSION = "1.0.0"
logger = logging.getLogger("phishing.api")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_PATHS = {"/predict", "/health", "/ready", "/model-info", "/metrics", "/docs", "/redoc", "/openapi.json"}
_BUSY = {503: {"model": ErrorResponse, "description": "Not ready, overloaded or timed out; retry after Retry-After"}}


@dataclass
class _State:
    metrics: Metrics = field(default_factory=Metrics)
    service: InferenceService | None = None
    load_error: str | None = None

    @property
    def ready(self) -> bool:
        return self.service is not None and self.service.running

    @property
    def model_version(self) -> str | None:
        return getattr(self.service.predictor, "model_version", None) if self.service is not None else None


def create_app(service_factory: Callable[[], InferenceService] | None = None,
               config: ApiConfig | None = None) -> FastAPI:
    """service_factory: builds the InferenceService at startup (default: from the
    files in models/ and config/). Tests pass a small one."""
    cfg = config or ApiConfig.from_file()
    factory = service_factory or InferenceService.from_files
    state = _State()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        start = time.perf_counter()
        try:
            state.service = await asyncio.to_thread(factory)
        except Exception as exc:                          # keep running: /ready explains
            state.load_error = f"{type(exc).__name__}: {exc}"
            logger.error("model NOT loaded: %s", state.load_error)
        else:
            logger.info("model %s loaded in %.2f s", state.model_version, time.perf_counter() - start)
        try:
            yield
        finally:
            if state.service is not None:
                await asyncio.to_thread(state.service.close, 30)   # answer what is queued, then stop

    app = FastAPI(title="Phishing detector API", version=API_VERSION, lifespan=lifespan,
                  docs_url="/docs" if cfg.docs_enabled else None,
                  redoc_url="/redoc" if cfg.docs_enabled else None,
                  description="Classifies URLs as phishing / uncertain / likely_safe. "
                              "`likely_safe` is never a guarantee, and a URL missing from threat "
                              "lists is not evidence of safety.")
    app.state.phishing = state
    app.add_middleware(RequestBodyLimitMiddleware, max_body_size=cfg.max_body_bytes)

    def retry_headers() -> dict[str, str]:
        return {"Retry-After": str(cfg.retry_after_seconds)}

    def busy(detail: str) -> HTTPException:
        return HTTPException(503, detail=detail, headers=retry_headers())

    def service() -> InferenceService:
        if not state.ready:
            raise busy(f"not ready: {state.load_error or 'the inference service is not running'}")
        return state.service

    def too_large() -> JSONResponse:
        return JSONResponse(status_code=413,
                            content={"detail": f"request body too large (at most {cfg.max_body_bytes} bytes)"})

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        rid = request.headers.get("x-request-id", "")
        request.state.request_id = rid if _REQUEST_ID.match(rid) else uuid.uuid4().hex
        start = time.perf_counter()
        length = request.headers.get("content-length", "")
        if length.isdigit() and int(length) > cfg.max_body_bytes:
            response = too_large()                        # refused before a byte of the body is read
        else:
            response = await call_next(request)
            if response.status_code == 413 and "json" not in response.headers.get("content-type", ""):
                response = too_large()                    # Starlette's limiter (body sent without a length)
        route = request.scope.get("route")
        endpoint = getattr(route, "path", None) or (request.url.path if request.url.path in _PATHS else "other")
        state.metrics.observe_request(endpoint, response.status_code, time.perf_counter() - start)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # FastAPI's default echoes the rejected input; it may be long or sensitive.
        detail = [{"loc": list(e.get("loc", ())), "msg": e.get("msg", ""), "type": e.get("type", "")}
                  for e in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": detail})

    @app.post("/predict", response_model=PredictResponse,
              responses={413: {"model": ErrorResponse, "description": "Body or URL list too large"},
                         500: {"model": ErrorResponse}, **_BUSY})
    async def predict(body: PredictRequest, request: Request) -> PredictResponse:
        svc = service()
        limit = svc.config.max_urls_per_request
        if len(body.urls) > limit:
            raise HTTPException(413, detail=f"too many URLs: {len(body.urls)} (at most {limit} per request)")
        rid, start = request.state.request_id, time.perf_counter()
        try:
            results = await asyncio.wait_for(svc.predict_async(body.urls, body.input_type),
                                             cfg.request_timeout_seconds)
        except Overloaded:
            raise busy("overloaded: too many URLs are queued") from None
        except QueueTimeout:                              # before TimeoutError: it is one
            raise busy("timed out waiting in the queue") from None
        except asyncio.TimeoutError:
            raise busy(f"timed out after {cfg.request_timeout_seconds} s") from None
        except ServiceClosed:
            raise busy("shutting down") from None
        except Exception as exc:                          # never return internals
            logger.error("predict id=%s failed: %s", rid, type(exc).__name__)
            raise HTTPException(500, detail="internal error") from None
        items = []
        for r in results:
            item = r.to_dict()
            item["decision"] = r.decision.lower() if r.decision else None
            items.append(item)
        state.metrics.observe_results(items)
        counts = Counter(i["decision"] or "invalid" for i in items)
        logger.info("predict id=%s type=%s urls=%d %s pending=%d cache_hits=%d %.1f ms", rid,
                    body.input_type, len(items), dict(sorted(counts.items())),
                    sum(bool(i["pending"]) for i in items), sum(i["cache_hit"] for i in items),
                    (time.perf_counter() - start) * 1000)
        if cfg.log_phishing_urls:
            for i in items:
                if i["decision"] == "phishing":
                    logger.info("phishing id=%s source=%s url=%s", rid, i["source"], redact_url(i["url"]))
        return PredictResponse(results=[PredictionItem(**i) for i in items],
                               model_version=state.model_version, request_id=rid)

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(status="ok")

    @app.get("/ready", response_model=ReadyResponse, responses={503: {"model": ReadyResponse}})
    async def ready():
        if state.ready:
            return ReadyResponse(ready=True, model_version=state.model_version)
        reason = state.load_error or ("loading" if state.service is None else "the inference service stopped")
        return JSONResponse(status_code=503, headers=retry_headers(),
                            content=ReadyResponse(ready=False, model_version=None, reason=reason).model_dump())

    @app.get("/model-info", responses=_BUSY)
    async def model_info() -> dict:
        svc = service()
        return _model_info(svc, cfg)

    @app.get("/metrics", response_class=PlainTextResponse)
    async def metrics() -> PlainTextResponse:
        stats = state.service.stats() if state.service is not None else None
        return PlainTextResponse(state.metrics.render(stats, state.ready, state.model_version),
                                 media_type=CONTENT_TYPE)

    return app


def _model_info(svc: InferenceService, cfg: ApiConfig) -> dict:
    p = svc.predictor
    info: dict = {"api_version": API_VERSION, "model_version": p.model_version,
                  "decisions": ["phishing", "uncertain", "likely_safe"],
                  "input_types": list(INPUT_TYPES)}
    if p.runtime is not None:
        m = p.runtime.bundle.manifest
        cal = m.get("calibrator", {})
        info["model"] = {
            "mode": m.get("mode"), "candidate": m.get("candidate"), "created_at": m.get("created_at"),
            "evaluated_per": m.get("unit"),
            "thresholds": {"phishing_if_p_above": cal.get("t_phishing"),
                           "likely_safe_if_p_below": cal.get("t_safe")},
            "error_budgets": m.get("budgets"), "validation": m.get("validation_crossfit"),
            "trained_with": m.get("versions")}
        info["input_types_scored_by_model"] = [p.runtime.mode]
    info["rules"] = {"popular_websites": len(p.popular), "redirector_domains": len(p.redirectors)}
    local = None
    if p.threat_db is not None:
        local = p.threat_db.stats()
        updated = local.get("feeds_updated_at")
        try:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(updated)
            local["stale"] = age > p.threat_db.stale_after
        except (TypeError, ValueError):
            local["stale"] = True
    info["threat_intel"] = {"local_feeds": local,
                            "online_enabled": [c.name for c in p.online],
                            "online_disabled": dict(p.online_disabled)}
    sc = svc.config
    info["limits"] = {"max_urls_per_request": sc.max_urls_per_request, "max_url_length": MAX_RAW_LENGTH,
                      "max_body_bytes": cfg.max_body_bytes,
                      "request_timeout_seconds": cfg.request_timeout_seconds,
                      "queue_timeout_seconds": sc.queue_timeout_seconds, "max_queue_urls": sc.max_queue_urls}
    return info


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1", help="127.0.0.1 = this machine only (default)")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--config", type=Path, default=CONFIG_PATH)
    ap.add_argument("--limit-concurrency", type=int, default=128,
                    help="open connections/tasks before uvicorn answers 503 (default 128)")
    ap.add_argument("--log-level", default="info", choices=["debug", "info", "warning", "error"])
    args = ap.parse_args(argv)
    import uvicorn
    logging.basicConfig(level=args.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    uvicorn.run(create_app(config=ApiConfig.from_file(args.config)), host=args.host, port=args.port,
                workers=1, log_level=args.log_level, limit_concurrency=args.limit_concurrency,
                timeout_keep_alive=5, server_header=False, access_log=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
