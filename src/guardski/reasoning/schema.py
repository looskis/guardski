from __future__ import annotations

from dataclasses import dataclass, field

CRITERION_KINDS = ("tcp_open", "http_status", "banner_contains", "tls_expiry", "custom")
ASSUMPTION_KINDS = ("graph_fact", "coverage", "reachability", "credential_scope", "manual")
TIERS = ("A", "B", "C")
NARRATIVE_ONLY = "narrative_only"


class PlanValidationError(ValueError):
    pass


@dataclass(frozen=True)
class Criterion:
    kind: str
    subject: str
    expected: str
    tolerance: str | None = None


@dataclass(frozen=True)
class Assumption:
    kind: str
    subject: str
    claim: str
    satisfied: bool | None = None
    checked_at: float | None = None


@dataclass(frozen=True)
class Citation:
    text_span: str
    finding_ids: tuple[str, ...] = ()
    asset_ids: tuple[str, ...] = ()
    fact_ids: tuple[str, ...] = ()
    coverage_refs: tuple[str, ...] = ()
    speculative: bool = False


@dataclass(frozen=True)
class Hypothesis:
    statement: str
    finding_ids: tuple[str, ...] = ()
    asset_ids: tuple[str, ...] = ()
    disproof: tuple[Criterion, ...] = ()


@dataclass(frozen=True)
class Step:
    ordinal: int
    intent: str
    proposed_action: str
    proposed_tier: str
    targets: tuple[str, ...] = ()
    asset_ids: tuple[str, ...] = ()
    fact_ids: tuple[str, ...] = ()
    finding_ids: tuple[str, ...] = ()
    parameters: dict = field(default_factory=dict)
    expected_observation: str = ""
    success_criteria: tuple[Criterion, ...] = ()
    stop_condition: str = ""
    preconditions: tuple[Assumption, ...] = ()
    requires_credentials: tuple[str, ...] = ()
    reversible: bool = True
    confidence_basis: tuple[str, ...] = ()


@dataclass(frozen=True)
class Plan:
    narrative: str
    citations: tuple[Citation, ...] = ()
    steps: tuple[Step, ...] = ()
    hypotheses: tuple[Hypothesis, ...] = ()
    assumptions: tuple[Assumption, ...] = ()
    model_confidence: str | None = None


def plan_json_schema() -> dict:
    criterion = {
        "type": "object",
        "required": ["kind", "subject", "expected"],
        "properties": {
            "kind": {"type": "string", "enum": list(CRITERION_KINDS)},
            "subject": {"type": "string"},
            "expected": {"type": "string"},
            "tolerance": {"type": ["string", "null"]},
        },
        "additionalProperties": False,
    }
    return {
        "type": "object",
        "required": ["narrative", "citations", "steps", "hypotheses"],
        "properties": {
            "narrative": {"type": "string"},
            "citations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["text_span"],
                    "properties": {
                        "text_span": {"type": "string"},
                        "finding_ids": {"type": "array", "items": {"type": "string"}},
                        "asset_ids": {"type": "array", "items": {"type": "string"}},
                        "fact_ids": {"type": "array", "items": {"type": "string"}},
                        "coverage_refs": {"type": "array", "items": {"type": "string"}},
                        "speculative": {"type": "boolean"},
                    },
                    "additionalProperties": False,
                },
            },
            "steps": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["intent", "proposed_action", "proposed_tier"],
                    "properties": {
                        "intent": {"type": "string"},
                        "proposed_action": {"type": "string"},
                        "proposed_tier": {"type": "string", "enum": list(TIERS)},
                        "targets": {"type": "array", "items": {"type": "string"}},
                        "asset_ids": {"type": "array", "items": {"type": "string"}},
                        "finding_ids": {"type": "array", "items": {"type": "string"}},
                        "fact_ids": {"type": "array", "items": {"type": "string"}},
                        "parameters": {"type": "object"},
                        "expected_observation": {"type": "string"},
                        "success_criteria": {"type": "array", "items": criterion},
                        "stop_condition": {"type": "string"},
                        "requires_credentials": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "reversible": {"type": "boolean"},
                    },
                    "additionalProperties": False,
                },
            },
            "hypotheses": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["statement"],
                    "properties": {
                        "statement": {"type": "string"},
                        "finding_ids": {"type": "array", "items": {"type": "string"}},
                        "asset_ids": {"type": "array", "items": {"type": "string"}},
                        "disproof": {"type": "array", "items": criterion},
                    },
                    "additionalProperties": False,
                },
            },
        },
        "additionalProperties": True,
    }


def _criterion(data: dict) -> Criterion:
    return Criterion(
        kind=str(data.get("kind", "custom")),
        subject=str(data.get("subject", "")),
        expected=str(data.get("expected", "")),
        tolerance=data.get("tolerance"),
    )


def from_dict(data: dict) -> Plan:
    if not isinstance(data, dict):
        raise PlanValidationError("plan must be a JSON object")
    narrative = data.get("narrative")
    if not isinstance(narrative, str) or not narrative.strip():
        raise PlanValidationError("plan.narrative must be a nonempty string")
    citations = []
    for item in data.get("citations", []):
        citations.append(
            Citation(
                text_span=str(item.get("text_span", "")),
                finding_ids=tuple(item.get("finding_ids", [])),
                asset_ids=tuple(item.get("asset_ids", [])),
                fact_ids=tuple(item.get("fact_ids", [])),
                coverage_refs=tuple(item.get("coverage_refs", [])),
                speculative=bool(item.get("speculative", False)),
            )
        )
    steps = []
    for index, item in enumerate(data.get("steps", [])):
        steps.append(
            Step(
                ordinal=int(item.get("ordinal", index)),
                intent=str(item.get("intent", "")),
                proposed_action=str(item.get("proposed_action", NARRATIVE_ONLY)),
                proposed_tier=str(item.get("proposed_tier", "A")),
                targets=tuple(item.get("targets", [])),
                asset_ids=tuple(item.get("asset_ids", [])),
                fact_ids=tuple(item.get("fact_ids", [])),
                finding_ids=tuple(item.get("finding_ids", [])),
                parameters=dict(item.get("parameters", {})),
                expected_observation=str(item.get("expected_observation", "")),
                success_criteria=tuple(_criterion(c) for c in item.get("success_criteria", [])),
                stop_condition=str(item.get("stop_condition", "")),
                requires_credentials=tuple(item.get("requires_credentials", [])),
                reversible=bool(item.get("reversible", True)),
            )
        )
    hypotheses = []
    for item in data.get("hypotheses", []):
        hypotheses.append(
            Hypothesis(
                statement=str(item.get("statement", "")),
                finding_ids=tuple(item.get("finding_ids", [])),
                asset_ids=tuple(item.get("asset_ids", [])),
                disproof=tuple(_criterion(c) for c in item.get("disproof", [])),
            )
        )
    return Plan(
        narrative=narrative,
        citations=tuple(citations),
        steps=tuple(steps),
        hypotheses=tuple(hypotheses),
        model_confidence=data.get("confidence"),
    )


def to_dict(plan: Plan) -> dict:
    from dataclasses import asdict

    return asdict(plan)


def _sentences(text: str) -> list[str]:
    import re

    parts = re.split(r"(?<=[.!?])\s+", text.strip())
    return [p for p in parts if p.strip()]


def validate_semantics(
    plan: Plan,
    *,
    known_findings: set[str],
    known_assets: set[str],
    known_facts: set[str],
    catalog: dict[str, dict],
    allow_cidrs: tuple[str, ...] = (),
    exclude_cidrs: tuple[str, ...] = (),
    credentials: tuple[str, ...] = (),
    offline_actions: tuple[str, ...] = ("recon.sbom_match",),
) -> list[str]:
    """Deterministic semantic validation. Returns rejection reasons; never repairs."""
    import ipaddress

    errors: list[str] = []

    def cite(ids, known, label):
        missing = set(ids) - known
        if missing:
            errors.append(f"{label} cite unknown id(s): {', '.join(sorted(missing))}")

    for citation in plan.citations:
        cite(citation.finding_ids, known_findings, "citation")
        cite(citation.asset_ids, known_assets, "citation")
        cite(citation.fact_ids, known_facts, "citation")
    for hypothesis in plan.hypotheses:
        cite(hypothesis.finding_ids, known_findings, "hypothesis")
        cite(hypothesis.asset_ids, known_assets, "hypothesis")
        for criterion in hypothesis.disproof:
            if criterion.kind not in CRITERION_KINDS:
                errors.append(f"hypothesis disproof has unknown criterion kind: {criterion.kind}")
    for step in plan.steps:
        cite(step.finding_ids, known_findings, "step")
        cite(step.asset_ids, known_assets, "step")
        cite(step.fact_ids, known_facts, "step")
        if step.proposed_tier not in TIERS:
            errors.append(f"step {step.ordinal}: invalid proposed_tier {step.proposed_tier}")
        if step.proposed_action != NARRATIVE_ONLY:
            spec = catalog.get(step.proposed_action)
            if spec is None:
                errors.append(f"step {step.ordinal}: unknown action {step.proposed_action}")
            else:
                if spec.get("tier") != step.proposed_tier:
                    errors.append(
                        f"step {step.ordinal}: tier {step.proposed_tier} != catalog "
                        f"{spec.get('tier')} for {step.proposed_action}"
                    )
                if step.proposed_action not in offline_actions and not step.targets:
                    errors.append(f"step {step.ordinal}: network action requires targets")
                if step.proposed_action not in offline_actions:
                    for field_name, value in (
                        ("expected_observation", step.expected_observation),
                        ("stop_condition", step.stop_condition),
                    ):
                        if not value.strip():
                            errors.append(f"step {step.ordinal}: missing {field_name}")
                    if not step.success_criteria:
                        errors.append(f"step {step.ordinal}: missing success_criteria")
        else:
            if step.targets:
                errors.append(f"step {step.ordinal}: narrative_only step must not target")
        for target in step.targets:
            try:
                network = ipaddress.ip_network(target, strict=False)
            except ValueError:
                continue
            for allowed in allow_cidrs:
                if not network.subnet_of(ipaddress.ip_network(allowed)):
                    errors.append(f"step {step.ordinal}: target {target} outside scope_allow")
            for excluded in exclude_cidrs:
                if network.overlaps(ipaddress.ip_network(excluded)):
                    errors.append(f"step {step.ordinal}: target {target} in scope_exclude")
        for criterion in step.success_criteria:
            if criterion.kind not in CRITERION_KINDS:
                errors.append(f"step {step.ordinal}: unknown criterion kind {criterion.kind}")
        missing_creds = set(step.requires_credentials) - set(credentials)
        if missing_creds:
            errors.append(
                f"step {step.ordinal}: credentials not in RoE: {', '.join(sorted(missing_creds))}"
            )
    return errors


def validate_citations(plan: Plan) -> list[str]:
    """Every narrative sentence must be grounded by a non-speculative citation span."""
    errors: list[str] = []
    spans = [c.text_span for c in plan.citations if c.text_span and not c.speculative]
    for sentence in _sentences(plan.narrative):
        if not any(span in sentence for span in spans):
            errors.append(f"narrative sentence is uncited: {sentence[:60]!r}")
    return errors


def derive_confidence(
    plan: Plan,
    *,
    severity_by_finding: dict[str, str],
    kev: set[str] | None = None,
    validated: set[str] | None = None,
    coverage_complete: bool = False,
) -> tuple[str, list[str]]:
    """Deterministic confidence; the model's own value is never used (SPEC §4.3)."""
    kev = kev or set()
    validated = validated or set()
    cited = {fid for s in plan.steps for fid in s.finding_ids}
    severities = {severity_by_finding.get(fid, "UNKNOWN") for fid in cited}
    basis: list[str] = []
    if kev & cited:
        basis.append("kev_member")
    if validated & cited:
        basis.append("validated")
    if coverage_complete:
        basis.append("coverage_complete")
    if "CRITICAL" in severities:
        basis.append("critical_path")
    if not cited:
        return "low", ["no_executable_steps"]
    if (kev & cited or validated & cited) and coverage_complete:
        return "high", basis
    if severities & {"CRITICAL", "HIGH"}:
        return "medium", basis
    return "low", basis
