"""Stable, local JSON contract handed to the Llama explanation layer.

The contract is intentionally small and text-free: no raw SMS body is included,
so a caller cannot accidentally log or transmit the message when passing the
result around. Evidence codes are stable machine-readable identifiers.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..config import LABELS, MODULE_NAME, RISK_LEVELS, SCHEMA_VERSION

EVIDENCE_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
ACTION_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


class SchemaError(ValueError):
    """Raised when a detection result violates the public contract."""


@dataclass(frozen=True)
class EvidenceItem:
    """One auditable detector finding. Never contains the message body."""

    code: str
    present: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.code, str) or not EVIDENCE_CODE_RE.match(self.code):
            raise SchemaError(f"Invalid evidence code: {self.code!r}")
        if not isinstance(self.present, bool):
            raise SchemaError("Evidence 'present' must be a boolean")

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "present": self.present}


@dataclass
class SmsDetectionResult:
    """The detector output consumed by risk fusion, UI and Llama explanation."""

    label: str
    risk_level: str
    scores: Mapping[str, float]
    evidence: list[EvidenceItem] = field(default_factory=list)
    recommended_action_codes: list[str] = field(default_factory=list)
    model_version: str = "sms-model-0.1"
    module: str = MODULE_NAME
    schema_version: str = SCHEMA_VERSION
    explanation_source: str = "detector_evidence"

    def __post_init__(self) -> None:
        # Accept strings or enums without importing enum semantics into callers.
        self.label = str(getattr(self.label, "value", self.label))
        self.risk_level = str(getattr(self.risk_level, "value", self.risk_level))
        self.evidence = [
            item if isinstance(item, EvidenceItem) else EvidenceItem(**item)
            for item in self.evidence
        ]
        self.recommended_action_codes = _dedupe(self.recommended_action_codes)
        self._validate()

    def _validate(self) -> None:
        if self.module != MODULE_NAME:
            raise SchemaError(f"module must be {MODULE_NAME!r}")
        if self.schema_version != SCHEMA_VERSION:
            raise SchemaError(f"schema_version must be {SCHEMA_VERSION!r}")
        if self.label not in LABELS:
            raise SchemaError(f"label must be one of {LABELS}")
        if self.risk_level not in RISK_LEVELS:
            raise SchemaError(f"risk_level must be one of {RISK_LEVELS}")
        if not isinstance(self.scores, Mapping):
            raise SchemaError("scores must be a mapping")
        if set(self.scores) != set(LABELS):
            raise SchemaError(f"scores must contain exactly {LABELS}")
        clean_scores: dict[str, float] = {}
        for label, value in self.scores.items():
            try:
                number = float(value)
            except (TypeError, ValueError) as exc:
                raise SchemaError(f"score for {label!r} is not numeric") from exc
            if not math.isfinite(number) or not 0.0 <= number <= 1.0:
                raise SchemaError(f"score for {label!r} must be in [0, 1]")
            clean_scores[label] = number
        total = sum(clean_scores.values())
        if not math.isclose(total, 1.0, abs_tol=0.02):
            raise SchemaError(f"scores must sum to approximately 1.0 (got {total})")
        self.scores = clean_scores
        seen: set[str] = set()
        for item in self.evidence:
            if item.code in seen:
                raise SchemaError(f"duplicate evidence code: {item.code}")
            seen.add(item.code)
        for action in self.recommended_action_codes:
            if not isinstance(action, str) or not ACTION_CODE_RE.match(action):
                raise SchemaError(f"Invalid action code: {action!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "schema_version": self.schema_version,
            "label": self.label,
            "risk_level": self.risk_level,
            "scores": {label: round(float(self.scores[label]), 6) for label in LABELS},
            "evidence": [item.to_dict() for item in self.evidence],
            "recommended_action_codes": list(self.recommended_action_codes),
            "model_version": self.model_version,
            "explanation_source": self.explanation_source,
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "SmsDetectionResult":
        evidence = payload.get("evidence", [])
        if not isinstance(evidence, Iterable):
            raise SchemaError("evidence must be a list")
        return cls(
            label=payload["label"],
            risk_level=payload["risk_level"],
            scores=payload["scores"],
            evidence=[EvidenceItem(**item) for item in evidence],
            recommended_action_codes=list(payload.get("recommended_action_codes", [])),
            model_version=payload.get("model_version", "unknown"),
            module=payload.get("module", MODULE_NAME),
            schema_version=payload.get("schema_version", SCHEMA_VERSION),
            explanation_source=payload.get("explanation_source", "detector_evidence"),
        )


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def json_schema() -> dict[str, Any]:
    """Return a self-contained JSON Schema for the public result contract."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://bharat-ai-2026.local/schemas/sms_detection_result.schema.json",
        "title": "SMS detection result",
        "description": "Local, text-free detector output for the Llama explanation layer.",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "module",
            "schema_version",
            "label",
            "risk_level",
            "scores",
            "evidence",
            "recommended_action_codes",
            "model_version",
            "explanation_source",
        ],
        "properties": {
            "module": {"const": MODULE_NAME},
            "schema_version": {"const": SCHEMA_VERSION},
            "label": {"enum": list(LABELS)},
            "risk_level": {"enum": list(RISK_LEVELS)},
            "scores": {
                "type": "object",
                "additionalProperties": False,
                "required": list(LABELS),
                "properties": {
                    label: {"type": "number", "minimum": 0, "maximum": 1}
                    for label in LABELS
                },
            },
            "evidence": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["code", "present"],
                    "properties": {
                        "code": {"type": "string", "pattern": "^[A-Z][A-Z0-9_]*$"},
                        "present": {"type": "boolean"},
                    },
                },
            },
            "recommended_action_codes": {
                "type": "array",
                "items": {"type": "string", "pattern": "^[A-Z][A-Z0-9_]*$"},
            },
            "model_version": {"type": "string", "minLength": 1},
            "explanation_source": {"const": "detector_evidence"},
        },
    }


def write_json_schema(path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(json_schema(), indent=2), encoding="utf-8")
    return path
