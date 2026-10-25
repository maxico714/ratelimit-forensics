from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Window:
    reset_seconds: float | None
    unit: str
    source: str

    def to_dict(self) -> dict[str, Any]:
        return {"reset": self.reset_seconds, "unit": self.unit, "source": self.source}


@dataclass
class Attribution:
    layer: str
    vendor: str | None
    confidence: float
    evidence: list[str] = field(default_factory=list)
    policy: str | None = None
    window: Window | None = None
    conflicts: list[str] = field(default_factory=list)
    insufficient_evidence: bool = False
    parsed: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "layer": self.layer,
            "vendor": self.vendor,
            "confidence": round(self.confidence, 3),
            "evidence": self.evidence,
            "policy": self.policy,
            "window": self.window.to_dict() if self.window else None,
            "conflicts": self.conflicts,
            "insufficient_evidence": self.insufficient_evidence,
            "parsed": self.parsed,
        }


@dataclass(frozen=True)
class Captured:
    status: int
    headers: dict[str, str]
    body: str = ""
    notes: tuple[str, ...] = ()
