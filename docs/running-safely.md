# Running the collectors safely

Evidence collection touches privileged settings on many systems. These rules keep the exercise
read-only, least-privilege and defensible in front of an auditor.

## 1. Read-only by design

* Every collector only **reads**. The only write is the evidence file itself. If you modify a collector,
  keep that property: no `Set-`, no `sudo <change>`, no `put_*` API calls.
* The Microsoft 365 scripts request **delegated, read-only Graph scopes** and sign in interactively.
  There is no application registration, no client secret and no certificate to protect.
* The cloud scripts need the `SecurityAudit` managed policy (AWS) or the `Reader` role (Azure) and nothing more.
* Nothing is sent anywhere: no telemetry, no upload, no e-mail. Transport is your job (section 4).

## 2. Least privilege per collector

| Collector family | Minimum identity | Why it is enough |
|------------------|------------------|------------------|
| Windows (local admin, patch, firewall) | Standard user | All queried through public cmdlets and registry keys readable by users |
| Windows (audit policy, BitLocker) | Local administrator, **not** domain admin | `auditpol` and `Get-BitLockerVolume` require elevation on the host only |
| Linux | `root` via `sudo` on the host, or a read-only account for the file-based subset | `sshd -T`, `auditctl`, `/etc/shadow` and sudoers are root-readable only |
| Microsoft 365 | Global Reader or Security Reader, with Reports Reader for MFA registration | Delegated read scopes; no write role needed |
| AWS | A role with `SecurityAudit` | Lists and gets only |
| Azure | `Reader` on the subscription(s) | ARM list/get only |

Use a **dedicated evidence-collection account** where you can (for example `svc-evidence` or
`evidence.reader@…`) so the `collected_by` field is unambiguous and its activity is easy to audit.
Never use a shared administrator account.

## 3. What the evidence may contain, and what it never contains

Contains: account names, group memberships, policy names, configuration values, package names,
tenant and subscription identifiers, bucket and storage-account names.

Never contains: password hashes, recovery keys, BitLocker recovery passwords, API keys, tokens, private
keys, sign-in logs with IP addresses, e-mail content. The collectors are written to skip those fields
(for example only the **type** of BitLocker key protector is recorded). Keep that line when you extend them.

Treat the output as **internal / confidential** anyway: a list of local administrators or a Conditional
Access configuration is useful to an attacker.

## 4. Where to store the evidence

1. Run the collector on the target and write to a local folder (`-OutputDirectory`, first argument for bash, `--output-dir`).
2. Verify immediately: `python scripts/verify_evidence.py <folder>`.
3. Move the files to the **evidence repository** for the audit cycle: a restricted SharePoint library,
   a GRC tool's evidence store, or a WORM-capable bucket. Access limited to the compliance team and the auditors.
4. Generate the manifest in the destination (`--manifest manifest.json`) and store the manifest's SHA-256
   in the audit log or the ticket. From then on any change to any file is detectable.
5. Delete the local copies on the target.

Suggested layout: `evidence/<audit-cycle>/<control-family>/<collector>_<host>_<timestamp>.json` plus one
`manifest.json` per cycle.

## 5. Sampling and frequency

Auditors accept samples, not populations. Decide the sample before collecting and record it:

| Scope | Typical sample | Frequency |
|-------|----------------|-----------|
| Workstations | 5–10 per OS image or per site, chosen at random | Quarterly |
| Servers | All in-scope servers if under 30, otherwise 10 % with every critical server included | Quarterly |
| Linux hosts | Same rule as servers | Quarterly |
| Entra ID tenant | Whole tenant (the scripts aggregate) | Monthly |
| Cloud accounts / subscriptions | All in scope | Monthly |

Collect at the **same point in time** across a sample (same day) so the auditor can correlate the files.

## 6. Retention

* Keep evidence for at least **one full certification cycle** (three years for ISO/IEC 27001) or the
  period your regulator requires, whichever is longer.
* Keep the **manifest** for as long as the evidence; it is what proves integrity.
* Evidence contains personal data (user names). Apply your data-protection retention rule and do not
  keep it longer than the audit purpose justifies.

## 7. Before you run anything

- [ ] Change ticket or audit plan references the collection (what, where, who, when).
- [ ] Dedicated read-only identity created and tested on one host.
- [ ] Target list and sample recorded.
- [ ] Output folder is local, restricted, and will be cleaned afterwards.
- [ ] You have read the collector you are about to run. They are short on purpose.

## 8. Testing changes

Never test against production. Run the Windows and Linux collectors on a lab VM; run the Microsoft 365
and cloud collectors against a test tenant or sandbox account. The repository's `examples/` folder is
generated from fictional data by `scripts/build_examples.py`; never replace it with real output.
