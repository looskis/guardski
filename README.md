# Guardski

Guardski is an open-source, self-hosted, on-prem agent that continuously validates an
organization's real exposure by fusing deterministic scanning (Trivy/Nuclei/Nmap) with
governed, model-agnostic agentic reasoning and exploitation, producing tamper-evident
audit evidence. It targets regulated, sovereign buyers who need the between-pentest
continuous-validation layer that SaaS and cloud-tethered tools cannot serve.

**Version 0.1 ships the deterministic scanning and evidence baseline.** The governed
agentic layer (target graph, scoped context, plan generation, signed RoE + policy gate,
tiered actions, discovery loop, hypothesis tracking, and compliance packs) is implemented
in `src/guardski/` per [the system spec](docs/spec.md); it defaults off (`reasoning_enabled
= false`) and is exercised by the test suite with a deterministic stub provider. See
[coverage and audit readiness](docs/coverage.md) for implemented checks, explicit gaps, and
proposed GitHub/source-code integrations.

## Installation

Homebrew (macOS and Linux):

```sh
brew install looskis/tap/guardski
guardski --version
```

From source:

```sh
uv sync --locked
uv run guardski --version
```

Both install the CLI only. Trivy, Nuclei, and Nmap remain separate binaries; see
[Quick start](#quick-start). Guardski is licensed under the
[GNU AGPL v3.0 or later](LICENSE).

## Implemented coverage

| Target kind | Engine | Checks |
| --- | --- | --- |
| `filesystem` | Trivy | Supported dependency manifests, IaC misconfigurations, exposed secrets |
| `rootfs` | Trivy | Supported OS packages and applications in an accessible root filesystem |
| `image` | Trivy | Container images fetched from an explicitly named registry |
| `archive` | Trivy | Exported Docker/OCI image archives; suitable for disconnected use |
| `sbom` | Trivy | Known vulnerabilities in supported SBOM formats |
| `web` | Nuclei | Explicitly approved, signed local HTTP/TLS/TCP/DNS templates |
| `network` | Nmap | TCP port/service inventory for explicit IPs or CIDRs |

Nmap observations are **INFO inventory**, not CVE findings. Nuclei coverage is only
as broad as the selected templates. Filesystem secret scanning covers the working
tree; it does not scan every historical Git commit. No scanner detects everything.

## Quick start

Requirements: Linux or macOS, Python 3.12+, and the scanner binaries required by
your targets. The container includes Trivy, Nuclei, and Nmap. Native installations
need them on PATH or configured as absolute paths.

The Trivy adapter was tested with **0.76.1** and the Nuclei adapter with **3.11.1**.
Use an organization-approved release and validate upgrades before production.
For installation, use the projects' official
[Trivy](https://trivy.dev/docs/latest/getting-started/installation/),
[Nuclei](https://docs.projectdiscovery.io/tools/nuclei/install), and
[Nmap](https://nmap.org/download.html) distribution instructions.

```sh
uv sync --locked
uv run guardski --config examples/guardski.toml check
uv run guardski --config examples/guardski.toml scan
uv run guardski --config examples/guardski.toml findings
uv run guardski --config examples/guardski.toml run
```

The example scans this checkout and writes private state to `.guardski/`.
Edit its targets and owners to match your environment. All local paths are
resolved relative to the configuration file. Do not put credentials in the config;
private-registry authentication can use the `TRIVY_USERNAME` and
`TRIVY_PASSWORD` environment variables supplied by your secret manager.

`check` validates configuration and binary availability. It does not test registry
credentials, template signatures, database downloads, or actual scan coverage.
An empty or invalid target set is rejected. Unknown configuration keys are errors.

## Scheduling and operations

- Use a five-field UTC `cron` expression or `interval_seconds` (minimum 10).
  Individual targets can override the global schedule with `[targets.schedule]`.
- `run_on_start = true` means an immediate run on first configuration or a scan
  policy change. An ordinary restart preserves the saved due time.
- Missed intervals coalesce into one run. The next run is scheduled from completion.
  Long scans execute sequentially; provision separate agents for large inventories.
- One agent/one-shot scanner holds the state-directory lock. The scanner subprocess
  inherits the lock so it survives an abrupt agent crash. Separate state directories
  do not coordinate with each other.
- A manual `scan` does not advance the recurring schedule. To scan manually while
  the daemon is active, stop it first; simultaneous scan runners are rejected.
- SIGTERM/SIGINT stop the active scanner process group. Scans have time and output
  limits. A restart marks unfinished records as interrupted and discards raw work
  files left by the previous process.
- Restart the daemon to apply configuration changes. Local SQLite WAL storage must
  be on a local filesystem, not NFS or a shared multi-host volume.

Useful commands:

```sh
uv run guardski --config examples/guardski.toml scan --target application
uv run guardski --config examples/guardski.toml status
uv run guardski --config examples/guardski.toml history --limit 20
uv run guardski --config examples/guardski.toml findings --overdue
uv run guardski --config examples/guardski.toml gate
```

Output is JSON on stdout; operational logs go to stderr. Timestamps in JSON are
Unix seconds in UTC. `health` checks the daemon heartbeat only. `status` and
`gate` surface configured targets that have never completed, failed, changed
policy, or become stale. They do not discover assets missing from your configuration.

`scan` exits 0 when all selected scanners complete, even if they find issues.
It exits 1 for a failed/interrupted scan. `gate` exits 1 for coverage gaps, open
HIGH/CRITICAL findings, or overdue remediation. Inventory-only findings do not
block the gate. Operational/configuration errors exit 2.

There is no built-in email, Slack, or ticket delivery yet. Connect the exit status,
JSON output, and service logs to your existing on-premises monitoring and
ticketing process. A passing gate is an operational policy result, not an audit opinion.

## Finding ownership and remediation

Findings have stable IDs based on target identity, rule, category, location, and
package. Package version changes preserve first-seen dates and remediation
deadlines. File/line changes can create a new finding. Duplicates within a scan are
collapsed. Successful rescans of a previously resolved issue reopen it.

```sh
guardski --config examples/guardski.toml triage FINDING_ID \
  --status in_progress --owner platform --actor alice \
  --reason "Tracked in SEC-123; patch rollout scheduled"

guardski --config examples/guardski.toml triage FINDING_ID \
  --status accepted_risk --actor security-owner \
  --risk-until 2026-12-01T00:00:00Z \
  --reason "Approved exception SEC-124; isolated service and compensating control"

guardski --config examples/guardski.toml triage FINDING_ID \
  --status resolved --actor reviewer \
  --reason "Patch deployed; verification evidence in SEC-123 and scan RUN_ID"
```

Risk acceptance requires an expiry; expired exceptions become effectively open.
The actor is operator-supplied metadata, **not authenticated identity**. Restrict
CLI/state access with OS accounts and your administrative access controls.

Absent findings are never automatically resolved, because changes in reachability,
rules, or scope can hide a previously observed issue. Resolution is a human review
with a recorded reason/evidence reference. Failures never mark issues fixed.
The default 7/30/90/180-day critical/high/medium/low SLAs are editable examples, not
deadlines mandated by SOC 2.

## Evidence

```sh
guardski --config examples/guardski.toml export --output evidence-2026-10-24.zip
guardski verify evidence-2026-10-24.zip
guardski --config examples/guardski.toml verify-audit
```

An evidence bundle contains a consistent SQLite backup, run history, findings,
configured coverage, a hash-chained activity log, configuration snapshots, engine
versions, selected template hashes, sanitized scanner reports, and a SHA-256
manifest. Vulnerability runs also record Trivy database metadata and its SHA-256.
A database older than `max_db_age_hours` (default 168) causes the run to fail.

Bundles include failures and still-running records; they do not imply all targets
passed. Export refuses changed stored artifacts or an invalid audit chain, and will
not overwrite an existing output. The printed bundle hash and chain head can be
retained by an independent archive.

Hashes detect accidental or uncoordinated changes. An administrator controlling
the agent can rewrite the database, history, and hashes. For audit retention,
archive exports in independently controlled immutable storage and retain/sign their
hashes there. Disk encryption, backups, authentication, approval workflows, and
retention policies belong to your deployment. There is no automatic deletion:
monitor disk space and archive under your approved retention policy.

State is created with private permissions, and the CLI applies umask 077. Treat all
reports as sensitive. Trivy secret matches/source snippets and Nuclei request/
response/extracted values are removed from retained reports, but paths, metadata,
URLs, and diagnostics can still be sensitive. Unprocessed scanner output exists
temporarily on disk during execution.

## Network access and disconnected installations

The agent does not upload scan results. By default, Trivy may download vulnerability
databases and explicitly configured registry images. Version checks and telemetry
are disabled, and dependency-analysis lookups are disabled. Misconfiguration checks
use the bundle embedded in the approved Trivy release.

Set `offline = true` to disable Trivy vulnerability/Java database updates too.
Use `archive` instead of registry `image` targets. Populate the cache on a connected
staging machine, then transfer it into the configured state directory:

```sh
trivy image --cache-dir ./trivy-cache --disable-telemetry --skip-version-check --download-db-only
trivy image --cache-dir ./trivy-cache --disable-telemetry --skip-version-check --download-java-db-only
```

Copy `trivy-cache/db/` and `trivy-cache/java-db/` under `STATE_DIR/cache/`, preserve
read permissions for the agent account, and refresh within your database-age policy.
Do this with the agent stopped. Install Python dependencies and scanner binaries
before disconnecting; use an internal package/image mirror where needed.
See [Trivy connectivity documentation](https://trivy.dev/docs/latest/guide/advanced/air-gap/).

Nuclei does not auto-download/update templates. Supply specific, reviewed, signed
local template files via `engines.nuclei_templates`. Unsigned templates, external
Interactsh callbacks, automatic redirects, code/headless/JavaScript templates, and
templates tagged dos/fuzz/bruteforce/intrusive are excluded. Signatures establish
provenance, not harmlessness. Review template requests and destinations for your scope.
Nonzero request-error counts or unconfirmed template execution fail coverage.

**Offline does not mean network isolation:** Nuclei and Nmap still contact explicitly
configured targets, and a template can contain its own destinations. Enforce egress
allowlists/firewall rules at deployment for strict on-premises boundaries. For
filesystem/archive-only offline container operation, a Compose override can set
`network_mode: none`.

## Deployment

For Docker Compose, edit [the container config](deploy/guardski.container.toml), then:

```sh
GUARDSKI_SCAN_PATH=/srv/application docker compose up --build -d
docker compose exec guardski guardski --config /etc/guardski/guardski.toml status
docker compose logs -f guardski
```

The container runs as UID/GID 10001, with a read-only root filesystem, dropped
capabilities, read-only target mounts, and a persistent state volume. Grant it read
access to the selected targets. It does not mount the Docker socket or the host
root by default. To scan a host root, add a deliberate read-only mount and a
`rootfs` target. Unreadable files and unsupported ecosystems reduce coverage.

Add read-only template, SBOM, and archive mounts as needed. Bridge networking may
not reach every internal network; configure routing explicitly. Database/registry
access needs working DNS and trusted internal CA certificates.

[The systemd unit](deploy/guardski.service) assumes a deployment at
`/opt/guardski`, a virtual environment at `/opt/guardski/.venv`, a dedicated
`guardski` account, and config at `/etc/guardski/guardski.toml`.
Set `state_dir = "/var/lib/guardski"`, install required binaries, grant target read
access, and install the unit under `/etc/systemd/system/`. Review its filesystem
restrictions for your host before enabling it.

Scanner images are pinned by version and digest; the Python runtime and OS packages receive
upstream updates at build time. For controlled production rollouts, pin image
digests and approve/record the resulting artifact in your own registry.

## Development and validation

```sh
uv sync --locked
uv run ruff check .
uv run ruff format --check .
uv run pytest
```

The tests cover configuration, scheduling persistence, exclusion of overlapping
runs, subprocess failures/timeouts/output bounds, result parsing/redaction,
finding lifecycle, database freshness, and evidence integrity. Tests use
deterministic scanner fixtures; real scanner smoke tests are additional validation.

The initial local validation also ran Trivy 0.76.1 against a temporary Dockerfile
and an outdated dependency manifest, and Nuclei 3.11.1 against a temporary loopback
HTTP service with an official signed template. Docker and Nmap were unavailable
on the development host, so container
build/startup and live Nmap execution still require deployment validation.
