from __future__ import annotations

import json

from .models import Attribution


def render_text(attribution: Attribution) -> str:
    vendor = f" ({attribution.vendor})" if attribution.vendor else ""
    confidence = f"[confidence: {attribution.confidence:.2f}]"
    if attribution.insufficient_evidence:
        confidence = "[insufficient evidence]"
    lines = [f"Layer:      {attribution.layer}{vendor} {confidence}".rstrip()]

    if attribution.evidence:
        lines.append(f"Evidence:   {attribution.evidence[0]}")
        for item in attribution.evidence[1:]:
            lines.append(f"            {item}")
    else:
        lines.append("Evidence:   none")

    lines.append(f"Policy:     {attribution.policy or 'unknown'}")

    if attribution.window is None:
        lines.append("Reset:      unknown")
    else:
        reset = attribution.window.reset_seconds
        pretty = f"{reset:g}s" if reset is not None else "unknown"
        lines.append(
            f"Reset:      {pretty} ({attribution.window.unit}, {attribution.window.source})"
        )

    for conflict in attribution.conflicts:
        lines.append(f"Note:       {conflict}")

    return "\n".join(lines) + "\n"


def render_json(attribution: Attribution) -> str:
    return json.dumps(attribution.to_dict(), indent=2, sort_keys=True) + "\n"
