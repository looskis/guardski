# Changelog

All notable changes to Guardski are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-10-18

### Added

- `guardski init` writes a commented starter configuration with one filesystem target,
  a daily schedule, and examples for rootfs and network targets.
- The Homebrew formula now installs Trivy, Nuclei, and Nmap, so a fresh install can run
  `check` and `scan` without extra setup.
- Formula caveats cover the config step, privilege requirements, and the optional local
  model endpoint.
- CI installs the formula on Linux from the working tree, runs the CLI, `guardski init`,
  `check`, and `brew test`.

### Changed

- Widened the optional `cryptography` constraint to `>=42`; the code works with current
  releases, including the one Homebrew ships.

## [0.1.0] - 2026-10-18

First public release: the deterministic scanning and evidence baseline plus the
governed agentic layer described in `docs/spec.md`.

### Added

- **Deterministic scanning** through Trivy (filesystem, rootfs, image, archive, SBOM),
  Nuclei (approved web templates), and Nmap (TCP service inventory), with typed
  findings, deduplication, and per-run artifacts.
- **Evidence and audit trail**: content-addressed artifacts, hash-chained audit events,
  signed evidence bundles, backup/restore, retention policies, and an `verify-audit`
  command.
- **Target graph and facts**: assets, services, findings, and evidence-backed facts
  (`host_observation`, `service_binding`, `banner`, `sbom_component`, `network_path`),
  with per-target coverage and blind-spot reporting.
- **Governed agent loop**: scoped context, model-agnostic plan generation (OpenAI-compatible
  endpoint or deterministic stub), evidence-based plan revalidation, plan dedup, and
  RBAC-checked approvals.
- **Rules of engagement and policy**: signed RoE, scope and intensity limits, tier
  ceilings, rate limiting, kill switch, and an execution gate that refuses unapproved
  plans.
- **Tiered actions**: read-only recon and confirmation (Tier A), gated validation and
  built-in proofs (Tier B: SSRF canary, hashed read, marker write, single credential
  check), and explicitly refused destructive categories (Tier C).
- **Credentialed inventory (Linux/SSH)**: fixed read-only `dpkg`/`rpm` and `ss`/`netstat`
  commands, producing `sbom_component` and `service_binding` facts. Secrets are resolved
  from `safeski:`/`env:`/`file:` references at execution time and never stored.
- **Network discovery**: opt-in host discovery, UDP scanning, OS detection, and
  `-Pn` over-report filtering so only hosts with observed services become assets.
- **Topology measurement**: `guardski topology trace` records traceroute paths and emits
  observed `path_via` and `same_segment` edges.
- **SBOM export**: CycloneDX 1.5 generated from observed components.
- **Agent eval harness**: `guardski eval` with deterministic KEV-prioritization,
  illegal-action, coverage-honesty, and plan-dedup scenarios.
- **Compliance reporting**, metrics, notifications (log/webhook/syslog), offline
  CMDB/identity ingestion, and an isolated lab under `lab/`.
- **Packaging**: Homebrew formula published through `looskis/tap`, signed release
  artifacts, and a tag-driven release workflow.

### Known gaps

- WinRM/Windows inventory and authenticated application/business-logic testing are not
  implemented.
- Topology is a measurement heuristic, not a firewall or segmentation audit.
- The SBOM is an inventory export from observed packages, not dependency resolution.
- The UI is deferred; everything is CLI-driven.
- Live cloud/identity/CMDB connectors and multi-host fleet aggregation are out of scope
  for this release.
