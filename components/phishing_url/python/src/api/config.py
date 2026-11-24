"""Settings of the HTTP API (config/api.json). Unknown keys are refused.

The queue and batch limits (URLs per request, queue size, queue timeout) are in
config/inference.json, because they belong to the inference service, which also
works without the API.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, fields
from pathlib import Path

CONFIG_PATH = Path("config/api.json")


@dataclass(frozen=True)
class ApiConfig:
    # 256 URLs x 8,192 characters (the normalizer's limit) is 2 MiB of URL text;
    # 4 MiB leaves room for JSON quoting. A larger body gets 413 before it is read.
    max_body_bytes: int = 4 * 2**20
    request_timeout_seconds: float = 15.0   # a whole /predict call; then 503 + Retry-After
    retry_after_seconds: int = 1            # sent with every 503
    docs_enabled: bool = True               # /docs and /redoc (their pages load scripts from a CDN)
    log_phishing_urls: bool = True          # log PHISHING verdicts, URL redacted (src.utils.redact)

    def __post_init__(self) -> None:
        for name in ("max_body_bytes", "retry_after_seconds"):
            v = getattr(self, name)
            if isinstance(v, bool) or not isinstance(v, int) or v < 1:
                raise ValueError(f"{name} must be an integer >= 1")
        t = self.request_timeout_seconds
        if isinstance(t, bool) or not isinstance(t, (int, float)) or not math.isfinite(t) or t <= 0:
            raise ValueError("request_timeout_seconds must be a number > 0")
        for name in ("docs_enabled", "log_phishing_urls"):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be true or false")

    @classmethod
    def from_file(cls, path: Path | str = CONFIG_PATH) -> "ApiConfig":
        path = Path(path)
        if not path.is_file():
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        allowed = {f.name for f in fields(cls)}
        if not isinstance(data, dict) or set(data) - allowed:
            raise ValueError(f"{path}: unknown keys {sorted(set(data) - allowed) if isinstance(data, dict) else data}")
        return cls(**data)
