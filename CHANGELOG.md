# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] — 2026-10-31

### Added
- Initial public release.
- Common evidence envelope `{control_ids, collector, host, collected_at_utc, collected_by, data, sha256}` with a
  byte-level SHA-256 scheme implemented identically in `lib/Evidence.psm1`, `lib/evidence.sh` and `lib/evidence.py`.
- Windows collectors (PowerShell): local administrators, patch status, audit policy, BitLocker, firewall profiles.
- Linux collectors (bash): SSH configuration, patch status, auditd, users and sudoers.
- Microsoft 365 collectors (PowerShell + Microsoft Graph, delegated read-only scopes, interactive sign-in):
  MFA registration, Conditional Access, guest inventory.
- Cloud collectors (Python, read-only): AWS S3 public access and encryption, Azure storage-account encryption and exposure.
- `scripts/verify_evidence.py`: recomputes every hash and prints or writes a manifest with its own SHA-256.
- `scripts/build_examples.py` and 14 fictional sample outputs in `examples/`.
- `docs/control-mapping.md` (ISO/IEC 27001:2022 Annex A and CIS v8 mapping, what the auditor looks for) and
  `docs/running-safely.md` (least privilege, read-only, storage, sampling, retention).
- CI on Windows and Ubuntu: PowerShell parsing, shellcheck, pyflakes, py_compile, cross-language hash round-trips,
  example verification and freshness.
- `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, Dependabot for GitHub Actions.
