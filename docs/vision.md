# Guardski — Product Vision

_Last updated: 2026-10-25_

## One sentence

**Guardski is an open-source, self-hosted agent that continuously validates an
organization's real exposure — fusing deterministic scanning with safe, governed,
agentic exploitation — and produces tamper-evident audit evidence, using the
organization's choice of local or cloud models.**

## The need we execute against

Regulated institutions (finance, health, government, critical infrastructure / OT)
have three unmet needs that no single tool serves well:

1. **Continuous, not point-in-time.** Annual pentests and quarterly scans go stale the
   day after they finish. Compliance regimes increasingly require testing _"after every
   significant change"_ (PCI DSS 11.4) and continuous validation (the CTEM model). Human
   pentest engagements cost $10k+ and take weeks — you cannot re-run them on every deploy.
2. **On-premise / sovereign.** The highest-value targets (core banking, OT/SCADA,
   air-gapped networks) cannot send topology, discovered credentials, or exploit proof to
   a vendor cloud. SaaS and cloud-tethered tools are a hard blocker here.
3. **Governed and evidence-producing.** Autonomous exploitation on production
   institutional networks is a liability unless it is scoped, authorized, blast-radius
   limited, and fully logged. Bug-hunting-oriented tools don't produce the audit artifact
   a QSA or regulator will accept.

Guardski exists to own the **continuous, on-prem, governed validation layer** — the
space _between_ the human pentests, not the human pentest itself.

## Positioning: enhancement, not replacement

We explicitly do **not** claim to replace the annual qualified-tester pentest mandated by
PCI DSS 11.4, DORA TLPT, or HIPAA. Those require a human attester, and overclaiming burns
us with the buyer's auditor. Instead:

- **Replace entirely:** the continuous / between-audit / "after significant change" layer,
  and frameworks that permit continuous monitoring as an alternative (e.g. FTC Safeguards).
- **Shrink dramatically:** the technical labor of the annual engagement (recon, chaining,
  proof-of-impact), so the human's job collapses from weeks of testing to a
  validation-and-attestation pass over Guardski's evidence.
- **Become the system of record:** reproducible, timestamped, scoped exploit proofs that a
  qualified tester _attests to_ rather than _generates_.

## What Guardski is — and is not

| Guardski IS | Guardski is NOT |
| --- | --- |
| Continuous, scheduled, governed exposure validation | A point-and-shoot "hack my app" bug finder |
| On-prem, self-hosted, zero mandatory egress | A SaaS / cloud control plane |
| An evidence-and-compliance engine | A bug-bounty replacement |
| Infra/exposure-chaining over real scan findings | A web-app pentest tool competing on raw exploitation |
| Model-agnostic (local or cloud) | Dependent on any one model vendor |
| Safety-first: scoped, tiered, logged | Autonomous with no blast-radius controls |

We do not compete with app-pentest bug-hunters (Strix, PentAGI, etc.) on their turf.
Different buyer, different job, different output.

## The moat: fusion + governance

The deterministic scanners already in Guardski (Trivy, Nuclei, Nmap) produce the **target
graph** the agent reasons over, and the agent's output flows back into the **same signed
evidence store**. Vuln-context is native, not bolted on. Two things competitors can't
easily copy:

1. **Detection is deterministic; only reasoning is agentic.** The accurate, boring work
   (CVE/config/service detection) is done by proven scanners — no LLM hallucination risk.
   The LLM only orchestrates and chains over _structured, verified_ findings. This makes
   weaker **local models viable**, which is precisely what the air-gapped buyer needs.
2. **Governance is first-class.** Every agent action is gated the same way Guardski
   already gates Nuclei templates — explicitly approved, signed, scoped — and written to a
   tamper-evident log that doubles as the compliance artifact.

## Architecture (built on the current repo)

Guardski 0.1 already provides: scheduled scanner orchestration, a local findings/evidence
store, integrity/signing discipline, and no telemetry or inbound API. The agentic layer
extends this — it does not replace it.

```
scan (Trivy/Nuclei/Nmap)  →  findings graph (store)
                                   │
                          agent: reason & plan chain
                                   │
                        policy engine: authorize each action   ← signed RoE
                                   │
                    tiered validation (confirm → safe-exploit → chain)
                                   │
                         signed evidence store  →  compliance report pack
```

**Design principles:**

- **The LLM plans; a deterministic policy engine authorizes.** The model never directly
  holds the trigger. Every action is checked against the rules-of-engagement before it
  fires — enforced in code, not prompt.
- **Model-agnostic via one `ModelProvider` interface.** Cloud (Anthropic / OpenAI /
  Bedrock) and local (Ollama / vLLM / llama.cpp), config-driven like the existing scanner
  adapters. **Local is the priority path**; cloud is a supported option.
- **Default-safe exploitation.** Tiers: (a) confirm-without-firing, (b) safe-exploit (no
  persistence), (c) full chain incl. lateral movement — each a separate consent gate.
  Full chain is opt-in, never default.
- **Everything is logged and signed.** The audit trail is a product feature, not an
  afterthought.

### Safety & authorization model

- **Machine-readable, signed rules-of-engagement (RoE):** IP/CIDR allowlists, excluded
  assets (DCs, payment switches, SCADA), time windows, max intensity. Customer co-signs;
  non-repudiable record.
- **Blast-radius control:** hard stops on destructive classes (no encryption, no exfil
  beyond canary tokens, no DoS); dry-run/simulation mode that reasons about a chain and
  reports "I could reach domain-admin via X→Y" without executing dangerous steps.
- **Accountability:** immutable tamper-evident action log, kill switch, automatic
  rollback/cleanup, and covert vs. transparent blue-team notification modes.

## Business model: open-core, Apache-2.0

The agent, scanners, local evidence store, model abstraction, policy engine, and CLI are
**free and self-hosted**. We monetize the governance/scale layer regulated buyers need:

| Open source (Apache-2.0) | Commercial |
| --- | --- |
| Agent, scanners, local store, model abstraction, policy engine, CLI | Fleet / multi-node orchestration |
| Single-host, local models | SSO/RBAC, signed compliance report packs (PCI/DORA/SOC2 mappings) |
| Community validation modules | Support SLA, indemnity, managed local-model tuning |
| | Optional hosted control plane |

Growth engine: "run it yourself, nothing leaves your network" + the compliance-evidence
angle the bug-hunters don't serve. Permissive licensing maximizes enterprise trust.

## Roadmap — biased for velocity

Each phase ships something usable. We earn the next phase by executing the current one.

- **Phase 0 — Foundation (done / hardening).** Deterministic scanning, scheduling, local
  evidence store, integrity/signing. _Already in repo._
- **Phase 1 — Agentic reasoning (read-only).** `ModelProvider` abstraction (local-first);
  agent reasons over the findings graph and produces an **exploitation plan + chain
  narrative** — no execution. Pure value, zero blast radius, immediately demoable. This is
  the fastest path to "wow" and validates the fusion thesis.
- **Phase 2 — Policy engine + Tier-A validation.** Signed RoE format; deterministic
  authorization gate; confirm-without-firing validation. Governance becomes real.
- **Phase 3 — Tier-B safe exploitation.** Non-destructive proof-of-impact, full action
  logging, cleanup/rollback. This is the differentiated product.
- **Phase 4 — Compliance report packs.** Map evidence to PCI 11.4 / CTEM / SOC 2. This is
  the first thing worth charging for.
- **Phase 5 — Tier-C chaining + fleet.** Opt-in lateral movement; multi-node orchestration
  (commercial).

## Success metrics (execution, not vanity)

- Time-to-first-value: `install → first validated chain narrative` in < 30 min.
- Runs fully air-gapped with a local model, zero egress — verifiable.
- Every action traces to a signed authorization and lands in the evidence log.
- A qualified pentester can attest to Guardski's evidence pack without re-doing the work.
- Adopted as the between-audit layer by a regulated design partner.

## Decisions locked

1. Enhancement, not replacement.
2. Regulated buyers; on-prem; local models prioritized, cloud supported.
3. Infra/exposure-chaining focus — not app-pentest bug-hunting.
4. Default-safe exploitation; full chain opt-in.
5. Open-core, Apache-2.0.
6. LLM plans, deterministic policy engine authorizes.
