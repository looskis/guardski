# Coverage, public data, and SOC 2 readiness

Guardski supports a vulnerability-management control. It cannot establish SOC 2
compliance by itself or promise coverage of every vulnerability. Audit scope,
system boundaries, policies, operating evidence, and the auditor's judgment determine
what is sufficient. The [AICPA SOC resources](https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services)
and [Trust Services Criteria](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022)
are the authoritative starting points.

## Public vulnerability intelligence

| Source | Use |
| --- | --- |
| [CVE List](https://github.com/CVEProject/cvelistV5) | Common identifiers and disclosure records |
| [NIST NVD](https://nvd.nist.gov/) | CVE enrichment, severity, and affected-product information |
| [OSV](https://osv.dev/) | Package- and version-oriented open-source advisories |
| [GitHub Advisory Database](https://github.com/github/advisory-database) | Reviewed and unreviewed ecosystem advisories; data used by Dependabot |
| Distribution/vendor advisories | OS package patches, including backported fixes |

This version relies on Trivy's maintained database for vulnerability matching.
It does not independently mirror, merge, or claim full coverage of these registries.
Template-based checks come from the approved local Nuclei templates. A CVE can
exist without a usable scanner check, and configuration/security-code findings
can exist without a CVE.

## Implemented versus additional coverage

| Area | Current implementation | Remaining coverage |
| --- | --- | --- |
| Asset inventory | Explicit target IDs, owners, Nmap TCP service observations | Reconciliation with authoritative CMDB, automatic discovery, asset lifecycle |
| OS and application packages | Trivy rootfs/filesystem/container/SBOM scans | Agent deployment on every host; Windows/macOS-specific authenticated checks |
| IaC and container configuration | Trivy built-in checks on readable files | Runtime hardening, cloud-account posture, comprehensive CIS benchmarks |
| Secrets | Trivy working-tree detection, redacted retained matches | Gitleaks/TruffleHog across Git history; rotation verification |
| Running web services | Approved Nuclei HTTP/TLS/TCP/DNS templates | Authenticated application coverage, business logic, ZAP sessions and API specs |
| Network | Nmap TCP connect/service inventory for explicit scope | UDP, authenticated appliance assessment, network segmentation verification |
| Source-code security | No native SAST adapter yet | Semgrep CE or licensed CodeQL; language/build-specific validation |
| GitHub security | No GitHub connector or alert ingestion yet | Dependabot, code-scanning, secret-scanning alert synchronization |
| Remediation | Owner, first/last seen, SLA, manual status, expiring exceptions | Ticket integrations, approval separation, escalation/notifications |
| Evidence | Persistent runs, errors, scanner/template/database provenance, hashes | Signed releases, independent immutable retention, authenticated actors |

The container includes the three implemented engines. Missing additional scanners
are roadmap items, not silently executed tools.

## Agent-assisted discovery and its declared blind spots

The agentic layer specified in [the spec](spec.md) adds capability without changing the
detection boundary:

- **Adds:** host-level assets discovered inside configured network targets, deterministic
  `asset_facts` (banners, TLS, package bindings), offline KEV/EPSS/CVSS enrichment,
  coverage and freshness metadata on every asset, scoped context for local models, and
  RoE-gated `recon.*` scan tasking (§4.1–§4.10).
- **Does not add:** asset discovery outside configured scope, cloud/SaaS inventory,
  identity/trust-graph analysis, authenticated application or business-logic testing, or
  any runtime network fetch. Those are open decisions or roadmap items, not implied
  capabilities (§12).
- **Does not weaken the zero-finding rule:** a target with no findings is only a clean
  result when `coverage_complete = true` and the relevant check ran. Failed, stale,
  narrowed, or template-changed scans produce a declared blind spot and cannot mark a
  finding remediated (§4.1, §5.7).

A deployment that needs the capabilities in the second list must not present this version
as covering them.

## GitHub and open-source scanner options

GitHub's security capabilities are complementary:

- [Dependabot alerts](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-alerts)
  compare the dependency graph with known advisories.
- [Code scanning](https://docs.github.com/en/code-security/concepts/code-scanning/code-scanning)
  can use CodeQL or third-party analysis results to report security flaws in code.
- [Secret scanning](https://docs.github.com/en/code-security/concepts/secret-security/secret-scanning)
  detects exposed credentials, including Git history.

[CodeQL](https://codeql.github.com/) is not an unrestricted open-source engine for
private commercial code. Review its terms and your GitHub Code Security entitlement.
GitHub-hosted alert ingestion also changes an on-premises-only data boundary;
GitHub Enterprise Server or locally retained scanner output may be appropriate.

Potential local adapters:

| Tool | Purpose |
| --- | --- |
| [Semgrep CE](https://github.com/semgrep/semgrep) | Source-code security checks with locally approved rules |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secret detection in Git history |
| [OSV-Scanner](https://google.github.io/osv-scanner/) | Open-source dependency checks |
| [Grype](https://github.com/anchore/grype) | Package/container/SBOM vulnerability matching |
| [ZAP](https://www.zaproxy.org/) | Dynamic web/API assessment with configured authentication and scope |

Prefer adding complementary coverage over counting duplicated CVEs from multiple
engines as independent issues. A future SARIF importer should preserve tool/rule,
commit, execution time, scan scope, and original evidence; importing yesterday's
report must not count as a fresh scan today.

## Suggested audit evidence use

This is an implementation-oriented mapping, not an auditor-approved control matrix:

| Control objective | Guardski evidence | Organizational evidence still needed |
| --- | --- | --- |
| Detect vulnerabilities and configuration changes | Scheduled run history, reports, tool and intelligence provenance | Approved scan scope/cadence; complete asset inventory; rule maintenance |
| Evaluate and prioritize security issues | Severity, first seen, owner, due date | Risk methodology, validation, business impact, review records |
| Remediate or accept risk | Triage history, expiry, repeat observations | Patch/change records, independent verification, authorized exception approval |
| Operate controls consistently over an audit period | Successful/failed/missed coverage and exported history | Alert response, periodic reviews, controlled retention and access |
| Preserve supporting evidence | Configuration snapshots, database/template hashes, checksummed export | Trusted timestamps, signatures/independent hash anchors, immutable archives |

A broader SOC 2 program also needs access provisioning/reviews, MFA, change
management, incident response, backup and recovery testing, vendor management,
security awareness, and other controls relevant to the selected Trust Services
Criteria. A vulnerability agent does not implement those controls.

## Deployment acceptance checklist

Before relying on this agent for production evidence:

1. Reconcile every in-scope asset with a configured target and accountable owner.
2. Approve the scan windows, rules/templates, database update process, egress policy,
   and remediation/exception deadlines.
3. Validate real scanner execution, required permissions, and negative controls on
   representative assets. A zero-finding report must still demonstrate coverage.
4. Connect operational failures, stale scans, and overdue findings to monitored
   escalation paths. Test that a deliberately failed scan reaches an operator.
5. Protect the service account and state, encrypt/back up evidence, and retain
   independent exports across the required review period.
6. Review scanner and agent updates, test restore/restart behavior, and perform
   independent security/penetration assessment where required by your program.

This checklist is deployment work; it has not been performed on your infrastructure.
