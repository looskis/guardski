# Guardski lab

An isolated lab for exercising the full loop: discovery scan -> graph -> plan -> approval
-> Tier-A validation -> proof -> re-scan -> evidence. **Run this only on a network and
hosts you own or are explicitly authorized to test.** Keep it off production networks.

## What the lab needs

- Docker or two throwaway VMs on an isolated bridge/VLAN:
  - `lab-app` (Linux, SSH enabled, a few services: 22, 80, 443, 5432/6379 optional)
  - `lab-win` (optional, Windows with WinRM — WinRM inventory is not built in yet)
- An operator workstation with the repo synced (`uv sync`), scanner binaries available, and
  a route to the lab subnet.
- A subnet small enough to be safe: `/24` or smaller. The agents enforce the configured
  scope; do not add the production LAN.

## 1. Point the config at the lab

Edit `lab/guardski.lab.toml`:

- uncomment the `[[targets]]` block for `lab-net` and set `value` to your lab CIDR;
- enable `udp`, `os_detection`, and `discovery` as desired (all default off; UDP and OS
  detection normally require root on the scanner host);
- add a `[[targets]]` entry for `lab-app` with `host = "<lab-app-ip>"` so Trivy results join
  the Nmap service inventory.

Discovery requires a reachable host and a scanner with the necessary privileges. `offline =
true` means Trivy cannot update its DB; populate the cache first or set it false for a
connected lab.

## 2. Operator key and RBAC (optional but recommended)

```sh
uv run python lab/keygen.py        # prints a private and public Ed25519 key
chmod 600 operator.key
```

Put the private key path in `[signing] private_key_path` and the public key under
`[rbac.roles]` for `plan_approver` / `dry_run_approver` / `credential_admin` to require
signed approvals. With no roles configured, `--actor` is recorded but not verified.

## 3. Credentialed inventory

```sh
uv run guardski --config lab/guardski.lab.toml credential add ssh-lab \
  --kind ssh_key --scope 10.10.10.0/24 --ref file:/absolute/path/to/lab.key --actor lab
```

The value is never stored; only the reference is. `recon.package_inventory` runs fixed,
read-only commands over SSH (`dpkg-query`/`rpm`, `ss`/`netstat`) and records `sbom_component`
and `service_binding` facts.

## 4. Scan, discover, plan, validate

```sh
uv run guardski --config lab/guardski.lab.toml scan --target lab-net
uv run guardski --config lab/guardski.lab.toml facts
uv run guardski --config lab/guardski.lab.toml sbom --output lab/sbom.json

uv run guardski --config lab/guardski.lab.toml discover --dry-run
uv run guardski --config lab/guardski.lab.toml discover
uv run guardski --config lab/guardski.lab.toml plans
uv run guardski --config lab/guardski.lab.toml show-plan <plan-id>

uv run guardski --config lab/guardski.lab.toml validate --plan <plan-id> --dry-run
uv run guardski --config lab/guardski.lab.toml approve-plan <plan-id> --actor lab
uv run guardski --config lab/guardski.lab.toml validate --plan <plan-id>
```

Tier-B proofs require a dry-run and `approve-dry-run` before execution. The dispatcher
enforces the gate; an unapproved plan cannot execute.

## 5. Topology and segmentation

```sh
uv run guardski --config lab/guardski.lab.toml topology trace --actor lab
```

This runs `traceroute` to every observed host, records `network_path` facts, and the graph
adds `path_via` and `same_segment` edges (observed, not inferred). It requires the
`traceroute` binary. Segmentation is a measurement heuristic, not a firewall audit.

## 6. Evidence, backup, and kill switch

```sh
uv run guardski --config lab/guardski.lab.toml export --output lab/evidence.zip --sign --key operator.key
uv run guardski --config lab/guardski.lab.toml backup --output lab/state-backup.zip
uv run guardski --config lab/guardski.lab.toml verify-audit
uv run guardski --config lab/guardski.lab.toml abort --actor lab
```

`abort` sets the persisted kill switch; new actions refuse until cleared. It does not
terminate a scanner subprocess that is already running (the scheduler's stop event does
that).

## 7. Agent eval harness

```sh
uv run guardski --config lab/guardski.lab.toml eval
```

Runs deterministic scenarios (KEV prioritization, illegal action rejection, coverage-gap
honesty, plan dedup) against the stub provider and reports a pass rate.

## 8. Local model

`[model]` is OpenAI-compatible. Point `endpoint` at Ollama, llama.cpp, or vLLM and set
`provider = "openai"`; no code change is needed. Keep the stub provider for CI.

## Known lab gaps

- WinRM inventory is not implemented (SSH only).
- UDP/OS detection depend on scanner privileges and may be noisy.
- Authenticated web/API testing is out of scope; `recon.auth_check` only confirms a
  credential works.
- Host discovery outside configured CIDRs is out of scope by design.
