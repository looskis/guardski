from __future__ import annotations

import json

from ..redact import redact_text
from .context import ContextBundle

PROMPT_VERSION = "1"

SYSTEM = (
    "You are Guardski's exploitation-planning agent. You reason only over the provided "
    "evidence. Never invent findings, assets, facts, or action ids. Coverage and blind "
    "spots are authoritative: absence of a finding is meaningful only when coverage is "
    "complete. Every narrative sentence must cite evidence. Reply with JSON only."
)


def render(bundle: ContextBundle) -> tuple[str, str]:
    """Return (system, user) prompt text rendered only from the redacted bundle."""
    payload = json.dumps(bundle.canonical(), sort_keys=True, indent=2)
    user, _ = redact_text(payload)
    return SYSTEM, user
