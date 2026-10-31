# Control mapping

Each collector is tagged with the controls it produces evidence for. The identifiers are references to
the standards by number only (ISO/IEC 27001:2022 Annex A and CIS Controls v8); the standards' text is not
reproduced here. The last column states what an auditor typically wants to see so you can judge whether
the collector's output is sufficient or needs a complementary document (policy, ticket, screenshot).

Identifier format used in the `control_ids` field: `ISO27001:A.8.8` (Annex A control 8.8) and `CIS8:7.3`
(CIS v8 safeguard 7.3).

## Windows (`collectors/windows/`)

| Collector | ISO/IEC 27001:2022 Annex A | CIS v8 safeguards | What the auditor is looking for | Run as |
|-----------|---------------------------|-------------------|---------------------------------|--------|
| `Get-LocalAdminEvidence.ps1` | A.5.15 Access control · A.5.18 Access rights · A.8.2 Privileged access rights | 4.7 Manage default accounts · 5.2 Unique passwords · 5.4 Restrict administrator privileges to dedicated accounts | Who is in the local Administrators group and whether that matches the approved list; built-in Administrator and Guest disabled; no enabled account without a password; local password and lockout policy values | Standard user (group members may need admin on some builds) |
| `Get-PatchStatusEvidence.ps1` | A.8.8 Management of technical vulnerabilities | 7.3 Automated OS patch management · 7.4 Automated application patch management | OS build and the date of the newest update against the patch SLA; no pending reboot older than the SLA; an update policy or WSUS/Intune assignment is in force; the update service runs | Standard user |
| `Get-AuditPolicyEvidence.ps1` | A.8.15 Logging | 8.2 Collect audit logs · 8.3 Ensure adequate audit log storage · 8.5 Collect detailed audit logs | Advanced audit policy subcategories match the logging standard (logon, process creation, policy change, account management); Security log large enough to cover the retention target; command-line and PowerShell logging enabled; Sysmon present where required | Local administrator for `auditpol` |
| `Get-BitLockerEvidence.ps1` | A.8.1 User endpoint devices · A.8.24 Use of cryptography | 3.6 Encrypt data on end-user devices · 3.11 Encrypt sensitive data at rest | OS and data volumes fully encrypted with an approved method (XTS-AES 256); TPM protector in use; recovery key escrowed (policy value), never the key itself | Local administrator |
| `Get-FirewallProfileEvidence.ps1` | A.8.20 Networks security · A.8.22 Segregation of networks | 4.4 Firewall on servers · 4.5 Firewall on end-user devices | All three profiles enabled with default inbound Block; blocked connections logged; the enabled inbound allow rules are justified (compare with the baseline) | Standard user |

## Linux (`collectors/linux/`)

| Collector | ISO/IEC 27001:2022 Annex A | CIS v8 safeguards | What the auditor is looking for | Run as |
|-----------|---------------------------|-------------------|---------------------------------|--------|
| `ssh-config-evidence.sh` | A.8.5 Secure authentication · A.8.9 Configuration management · A.8.20 Networks security | 3.10 Encrypt sensitive data in transit · 4.1 Secure configuration process | Root login and password authentication disabled, key-based or MFA authentication, modern ciphers/MACs/KEX, idle timeout, verbose logging; config and host keys owned by root with restrictive permissions; the effective config (`sshd -T`) matches the hardening standard | root for `sshd -T` |
| `patch-status-evidence.sh` | A.8.8 Management of technical vulnerabilities | 7.3 Automated OS patch management · 7.4 Automated application patch management | No security updates pending beyond the SLA; last update run recent; running kernel is the newest installed; reboot not pending for weeks; automatic updates configured where the policy says so | Standard user (root for dnf/zypper caches) |
| `auditd-evidence.sh` | A.8.15 Logging · A.8.16 Monitoring activities | 8.2 Collect audit logs · 8.5 Collect detailed audit logs · 8.9 Centralise audit logs | auditd active and enabled at boot; rules cover identity files, sudoers, privileged commands and are immutable (`-e 2`); log rotation and disk-full behaviour defined; journald persistent; logs forwarded to a central collector | root |
| `users-sudoers-evidence.sh` | A.5.15 Access control · A.5.16 Identity management · A.5.18 Access rights · A.8.2 Privileged access rights | 5.1 Inventory of accounts · 5.2 Unique passwords · 5.4 Restrict administrator privileges | Only `root` with UID 0; interactive accounts match the approved list; service accounts locked; password ageing in line with policy; sudo limited to named groups; NOPASSWD entries justified and scoped to specific commands | root for `/etc/shadow` and sudoers |

## Microsoft 365 / Entra ID (`collectors/m365/`)

| Collector | ISO/IEC 27001:2022 Annex A | CIS v8 safeguards | What the auditor is looking for | Graph scopes (delegated, read-only) |
|-----------|---------------------------|-------------------|---------------------------------|-------------------------------------|
| `Get-MfaRegistrationEvidence.ps1` | A.5.17 Authentication information · A.8.5 Secure authentication | 6.3 Require MFA for externally exposed applications · 6.5 Require MFA for administrative access | Share of members registered for MFA (target 100 % of active accounts); zero admins without MFA; strong methods (Authenticator, FIDO2/passkeys, Windows Hello) dominate; SSPR registration for the help-desk process | `UserAuthenticationMethod.Read.All`, `AuditLog.Read.All` |
| `Get-ConditionalAccessEvidence.ps1` | A.5.15 Access control · A.8.3 Information access restriction · A.8.5 Secure authentication | 6.3 · 6.4 Require MFA for remote network access · 6.5 | Enabled policies that require MFA for all users and phishing-resistant MFA for admin roles; legacy authentication blocked; risk-based policies; exclusions limited to break-glass accounts; report-only policies have a go-live plan | `Policy.Read.All` |
| `Get-GuestInventoryEvidence.ps1` | A.5.16 Identity management · A.5.18 Access rights · A.5.19 Information security in supplier relationships | 5.1 Inventory of accounts · 5.3 Disable dormant accounts · 6.1 Access granting process | Guest count and home domains match the known partner list; pending invitations and dormant guests (90+ days) are removed on a cadence; invitation rights limited to admins or guest inviters; guest permissions restricted | `User.Read.All`, `AuditLog.Read.All`, `Policy.Read.All` |

## Cloud (`collectors/cloud/`)

| Collector | ISO/IEC 27001:2022 Annex A | CIS v8 safeguards | What the auditor is looking for | Identity / permissions |
|-----------|---------------------------|-------------------|---------------------------------|------------------------|
| `aws_s3_public_access.py` | A.5.23 Information security for use of cloud services · A.8.3 Information access restriction · A.8.24 Use of cryptography | 3.3 Configure data access control lists · 3.11 Encrypt sensitive data at rest · 8.5 Collect detailed audit logs | Account-level Block Public Access fully on; no bucket public by policy or ACL unless documented (static website); default encryption on every bucket (KMS for sensitive data); access logging and versioning on buckets in scope | `SecurityAudit` managed policy or the listed `s3:Get*`/`s3:List*` actions |
| `azure_storage_encryption.py` | A.5.23 · A.8.20 Networks security · A.8.24 Use of cryptography | 3.3 · 3.10 Encrypt sensitive data in transit · 3.11 | HTTPS only and TLS 1.2 minimum on every account; public blob access disabled; shared-key access disabled where Entra authentication is possible; network default action Deny with private endpoints for sensitive data; customer-managed keys and infrastructure encryption where the classification requires them | `Reader` role on the subscription |

## Coverage summary by control

| Control | Collectors |
|---------|-----------|
| ISO27001:A.5.15 | Get-LocalAdminEvidence, Get-ConditionalAccessEvidence, users-sudoers-evidence |
| ISO27001:A.5.16 | Get-GuestInventoryEvidence, users-sudoers-evidence |
| ISO27001:A.5.17 | Get-MfaRegistrationEvidence |
| ISO27001:A.5.18 | Get-LocalAdminEvidence, Get-GuestInventoryEvidence, users-sudoers-evidence |
| ISO27001:A.5.19 | Get-GuestInventoryEvidence |
| ISO27001:A.5.23 | aws_s3_public_access, azure_storage_encryption |
| ISO27001:A.8.1 | Get-BitLockerEvidence |
| ISO27001:A.8.2 | Get-LocalAdminEvidence, users-sudoers-evidence |
| ISO27001:A.8.3 | Get-ConditionalAccessEvidence, aws_s3_public_access |
| ISO27001:A.8.5 | Get-MfaRegistrationEvidence, Get-ConditionalAccessEvidence, ssh-config-evidence |
| ISO27001:A.8.8 | Get-PatchStatusEvidence, patch-status-evidence |
| ISO27001:A.8.9 | ssh-config-evidence |
| ISO27001:A.8.15 | Get-AuditPolicyEvidence, auditd-evidence |
| ISO27001:A.8.16 | auditd-evidence |
| ISO27001:A.8.20 | Get-FirewallProfileEvidence, ssh-config-evidence, azure_storage_encryption |
| ISO27001:A.8.22 | Get-FirewallProfileEvidence |
| ISO27001:A.8.24 | Get-BitLockerEvidence, aws_s3_public_access, azure_storage_encryption |
| CIS8:3.3 / 3.6 / 3.10 / 3.11 | Get-BitLockerEvidence, ssh-config-evidence, aws_s3_public_access, azure_storage_encryption |
| CIS8:4.1 / 4.4 / 4.5 / 4.7 | ssh-config-evidence, Get-FirewallProfileEvidence, Get-LocalAdminEvidence |
| CIS8:5.1 / 5.2 / 5.3 / 5.4 | Get-LocalAdminEvidence, users-sudoers-evidence, Get-GuestInventoryEvidence |
| CIS8:6.1 / 6.3 / 6.4 / 6.5 | Get-GuestInventoryEvidence, Get-MfaRegistrationEvidence, Get-ConditionalAccessEvidence |
| CIS8:7.3 / 7.4 | Get-PatchStatusEvidence, patch-status-evidence |
| CIS8:8.2 / 8.3 / 8.5 / 8.9 | Get-AuditPolicyEvidence, auditd-evidence, aws_s3_public_access |

Technical evidence proves that a control is **implemented** on the sampled systems at a point in time.
It does not prove the control is **designed** correctly or **operated** continuously; pair it with the
policy, the procedure and a sampling plan (see [running-safely.md](running-safely.md)).
