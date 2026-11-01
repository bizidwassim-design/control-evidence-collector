# Control Evidence Collector Scripts

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) [![CI](https://github.com/bizidwassim-design/control-evidence-collector/actions/workflows/ci.yml/badge.svg)](https://github.com/bizidwassim-design/control-evidence-collector/actions/workflows/ci.yml) [![Fictional data](https://img.shields.io/badge/sample%20data-fictional-informational)](SECURITY.md)

Read-only scripts that collect **technical evidence for ISO/IEC 27001:2022 and CIS Controls v8** from
Windows, Linux, Microsoft 365 and cloud accounts, and write it as **timestamped JSON with an embedded
SHA-256**. The auditor gets reproducible, hashed artefacts; you get a manifest that proves nothing changed
between collection and review.

> 🇫🇷 Résumé en français en bas de page.

## Layout

```
lib/
  Evidence.psm1              PowerShell helper: envelope, hash, write, verify
  evidence.sh                bash helper: JSON builders, envelope, hash, write, verify (no jq)
  evidence.py                Python helper: envelope, hash, write, verify
collectors/
  windows/                   Get-LocalAdminEvidence, Get-PatchStatusEvidence, Get-AuditPolicyEvidence,
                             Get-BitLockerEvidence, Get-FirewallProfileEvidence        (PowerShell 5.1 / 7)
  linux/                     ssh-config, patch-status, auditd, users-sudoers           (bash)
  m365/                      Get-MfaRegistrationEvidence, Get-ConditionalAccessEvidence,
                             Get-GuestInventoryEvidence                               (Microsoft.Graph, read-only)
  cloud/                     aws_s3_public_access.py, azure_storage_encryption.py     (boto3 / Azure SDK, read-only)
scripts/
  verify_evidence.py         recomputes every hash in a folder, prints or writes a manifest
  build_examples.py          regenerates examples/ from fictional data
examples/                    14 fictional sample outputs (Northwind Logistics), one per collector
docs/
  control-mapping.md         collector -> ISO 27001 Annex A id + CIS v8 safeguard + what the auditor looks for
  running-safely.md          least privilege, read-only, where to store evidence, sampling, retention
```

## Quick start

```powershell
# Windows host, standard user is enough for most collectors
.\collectors\windows\Get-PatchStatusEvidence.ps1 -OutputDirectory C:\Evidence\2026-Q4
```

```bash
# Linux host
sudo ./collectors/linux/ssh-config-evidence.sh /var/tmp/evidence/2026-Q4
```

```powershell
# Microsoft 365: interactive sign-in, delegated read-only scopes, nothing stored
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Reports -Scope CurrentUser
.\collectors\m365\Get-MfaRegistrationEvidence.ps1 -OutputDirectory C:\Evidence\2026-Q4
```

```bash
# Cloud (read-only identities: SecurityAudit on AWS, Reader on Azure)
pip install boto3 && python collectors/cloud/aws_s3_public_access.py --profile audit --output-dir evidence/2026-Q4
pip install azure-identity azure-mgmt-storage azure-mgmt-resource && python collectors/cloud/azure_storage_encryption.py --output-dir evidence/2026-Q4
```

Then verify and build the manifest the auditor will keep:

```bash
python scripts/verify_evidence.py evidence/2026-Q4 --manifest evidence/2026-Q4/manifest.json
```

```
STATUS  COLLECTOR                            HOST        COLLECTED_AT_UTC      SHA256 (first 16)  FILE
----------------------------------------------------------------------------------------------------------------
OK      windows/Get-PatchStatusEvidence.ps1  NW-WS-0421  2026-10-15T09:30:00Z  2fecc88143da922f   Get-PatchStatusEvidence_NW-WS-0421_20261015T093000Z.json
OK      linux/ssh-config-evidence.sh         nw-app-07   2026-10-15T09:30:00Z  8ab405fd57375328   ssh-config-evidence_nw-app-07_20261015T093000Z.json
...
14 OK, 0 failed, 14 total. Manifest SHA-256: e53e33a7877e0fed…
```

Try it without touching anything: `python scripts/verify_evidence.py examples/`.

## The evidence envelope

Every collector, in every language, writes the same shape:

```json
{
  "control_ids": ["ISO27001:A.8.8", "CIS8:7.3", "CIS8:7.4"],
  "collector": "windows/Get-PatchStatusEvidence.ps1",
  "host": "NW-WS-0421",
  "collected_at_utc": "2026-10-15T09:30:00Z",
  "collected_by": "NORTHWIND\\svc-evidence",
  "data": { "...collector-specific, always with a summary block..." },
  "sha256": "2fecc88143da922ffada23e6dadab80a34b64b3a43ce611ed5d9739848803edb"
}
```

**How the hash works.** The file is serialised with `sha256` set to 64 zeros, the SHA-256 of those exact
bytes is computed, and the zeros are replaced by the digest. To verify, replace the digest with zeros and
hash again. Because this operates on bytes, a file written by PowerShell can be verified by bash or Python
and vice versa, with no JSON canonicalisation to get wrong. CI proves the round-trip in all directions.

File names: `<collector>_<host>_<timestamp>.json`. Tenant and account collectors use `host` values such as
`entra-tenant:<id>`, `aws-account:<id>`, `azure-subscription:<id>`.

## What's inside

| Collector | Evidence for | Minimum identity |
|-----------|--------------|------------------|
| `windows/Get-LocalAdminEvidence.ps1` | Local Administrators members, local accounts, password/lockout policy | Standard user |
| `windows/Get-PatchStatusEvidence.ps1` | OS build, installed updates and their age, pending reboot, update policy | Standard user |
| `windows/Get-AuditPolicyEvidence.ps1` | Advanced audit policy, event-log sizes and retention, PowerShell and command-line logging, Sysmon | Local administrator |
| `windows/Get-BitLockerEvidence.ps1` | Volume encryption status and method, protector **types**, TPM, policy | Local administrator |
| `windows/Get-FirewallProfileEvidence.ps1` | Profile state, default actions, logging, rule counts, enabled inbound allow rules | Standard user |
| `linux/ssh-config-evidence.sh` | Effective sshd settings, hardening directives, file permissions, service state | root for `sshd -T` |
| `linux/patch-status-evidence.sh` | Pending updates (apt/dnf/yum/zypper), last update run, kernel, reboot flag, auto-updates | Standard user |
| `linux/auditd-evidence.sh` | auditd state, loaded rules, rules files with hashes, auditd.conf, journald, syslog forwarding | root |
| `linux/users-sudoers-evidence.sh` | Login accounts with lock state and password age (never hashes), UID 0, sudo groups, sudoers lines | root |
| `m365/Get-MfaRegistrationEvidence.ps1` | MFA registered / capable / passwordless, admins without MFA, method distribution | Global Reader or Reports Reader |
| `m365/Get-ConditionalAccessEvidence.ps1` | Every CA policy (state, assignments as counts, conditions, controls) and derived checks | Global Reader or Security Reader |
| `m365/Get-GuestInventoryEvidence.ps1` | Guest counts, pending invitations, dormant guests, home domains, collaboration settings | Global Reader |
| `cloud/aws_s3_public_access.py` | Account and bucket Block Public Access, policy/ACL exposure, default encryption, logging, versioning | `SecurityAudit` |
| `cloud/azure_storage_encryption.py` | Key source, infrastructure encryption, HTTPS/TLS, public blob access, shared key, network rules | `Reader` |

Each collector header lists the exact control identifiers; the full table with "what the auditor is
looking for" is in [docs/control-mapping.md](docs/control-mapping.md).

## Design choices

* **Read-only, no stored credentials.** Local collectors use built-in cmdlets and files; Microsoft 365
  collectors use interactive sign-in with delegated read scopes; cloud collectors use the SDK credential
  chain. No app secrets, no certificates, no tokens on disk.
* **Secrets are structurally excluded.** BitLocker protector types but never recovery passwords; shadow
  lock state but never hashes; policy names but never key material.
* **Failures are evidence too.** Each step runs under `Invoke-EvidenceStep`, `evidence_command` or
  `try/except`; a missing privilege is recorded in that section and the rest is still collected.
* **One envelope, three implementations, byte-level hashing.** Verification never depends on which tool
  wrote the file, and `verify_evidence.py` produces a manifest with its own SHA-256 to pin a whole evidence set.
* **No dependencies beyond the obvious.** bash needs no `jq`; PowerShell needs no module except Microsoft.Graph
  for the tenant collectors; Python needs only the SDK of the cloud you query.
* **Reproducible samples.** `examples/` is generated from fictional data with fixed timestamps; CI rebuilds
  it and fails if it drifts, verifies every hash, and checks that a tampered file is rejected.

## How it relates to the sibling repositories

| Repository | Relationship |
|------------|--------------|
| [grc-control-crosswalk](https://github.com/bizidwassim-design/grc-control-crosswalk) | Translate the `control_ids` in each envelope to NIST CSF, SOC 2 or other frameworks. |
| [iso27001-iso42001-toolkit](https://github.com/bizidwassim-design/iso27001-iso42001-toolkit) | The Statement of Applicability and policies that these artefacts back up at audit time. |
| [ciso-executive-dashboard](https://github.com/bizidwassim-design/ciso-executive-dashboard) | Feed the `summary` blocks (MFA coverage, patch age, encryption rate) into the KPI views. |
| [soc-detection-playbooks](https://github.com/bizidwassim-design/soc-detection-playbooks) | Audit-policy and auditd evidence shows whether the telemetry the rules need is actually enabled. |
| [application-risk-assessment-template](https://github.com/bizidwassim-design/application-risk-assessment-template) | Use collected evidence to justify residual-risk scores for the controls listed per application. |
| [public-scripts](https://github.com/bizidwassim-design/public-scripts) | Broader operational scripts; this repository keeps only read-only, audit-grade collectors. |

## Contributing

New read-only collectors (macOS, Google Workspace, GCP, Kubernetes), better derived checks and mapping
corrections are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).
Run the checks listed there before opening a pull request.

## Disclaimer

These scripts show how a control is implemented on the systems you sample at the moment you run them.
They do not assess control design or continuous operation, and they are not legal or audit advice. Review
each script before running it in your environment, use a dedicated read-only identity, and handle the
output as confidential: it contains account and configuration details. All sample data is fictional.

## AI assistance

Built with Claude Code as a coding and writing assistant, which is why it appears as a co-author on some commits.
**Editor and reviewer: Wassim Bizid**, who set the scope, the frameworks and the GRC approach, edited the content
and decided what was published. Automated tests in CI check the published outputs. This is a maintainer review,
not an independent one.

## License

[MIT](LICENSE) — free to use, copy, modify and redistribute.

---

## 🇫🇷 Résumé

Scripts **open source et en lecture seule** qui collectent des preuves techniques pour **ISO/IEC 27001:2022**
et **CIS Controls v8** sur Windows (PowerShell), Linux (bash), Microsoft 365 (Microsoft Graph, connexion
interactive sans identifiant stocké) et le cloud (AWS S3, Azure Storage, Python). Chaque script écrit une
enveloppe JSON identique (`control_ids`, `collector`, `host`, `collected_at_utc`, `collected_by`, `data`,
`sha256`) dont l'empreinte SHA-256 se vérifie depuis n'importe quel langage ; `scripts/verify_evidence.py`
recalcule les empreintes d'un dossier et produit un manifeste. Correspondance des contrôles et guide
d'exécution sûre dans `docs/`. Les exemples (« Northwind Logistics ») sont fictifs. Licence MIT.
