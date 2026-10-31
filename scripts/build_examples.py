#!/usr/bin/env python3
"""Generate the fictional sample outputs in examples/ (one per collector) with the real envelope code.

Everything here describes "Northwind Logistics", a fictional company. Hostnames, users, tenant and
account identifiers are invented. Timestamps are fixed so the files are reproducible and CI can check
them with `git diff --exit-code examples/`.

Usage: python scripts/build_examples.py
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
from evidence import build_envelope, write_evidence  # noqa: E402

EXAMPLES = ROOT / "examples"
AT = "2026-10-15T09:30:00Z"
TENANT = "11111111-2222-3333-4444-555555555555"
SUBSCRIPTION = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
AWS_ACCOUNT = "123456789012"


def example(control_ids: list[str], collector: str, data: Any, host: str, by: str) -> Path:
    env = build_envelope(control_ids, collector, data, host=host, collected_by=by, collected_at_utc=AT)
    return write_evidence(env, EXAMPLES)


# ----------------------------------------------------------------------------- Windows

def windows_examples() -> list[Path]:
    host, by = "NW-WS-0421", "NORTHWIND\\svc-evidence"
    out = []
    out.append(example(
        ["ISO27001:A.5.15", "ISO27001:A.5.18", "ISO27001:A.8.2", "CIS8:4.7", "CIS8:5.2", "CIS8:5.4"],
        "windows/Get-LocalAdminEvidence.ps1",
        {
            "administrators_group": {
                "source": "Get-LocalGroupMember",
                "member_count": 3,
                "members": [
                    {"name": "NW-WS-0421\\Administrator", "object_class": "User", "principal_source": "Local", "sid": "S-1-5-21-1000000001-2000000002-3000000003-500"},
                    {"name": "NORTHWIND\\GG-Workstation-Admins", "object_class": "Group", "principal_source": "ActiveDirectory", "sid": "S-1-5-21-4000000004-5000000005-6000000006-1105"},
                    {"name": "NW-WS-0421\\laps-admin", "object_class": "User", "principal_source": "Local", "sid": "S-1-5-21-1000000001-2000000002-3000000003-1001"},
                ],
            },
            "local_users": [
                {"name": "Administrator", "enabled": False, "is_builtin_admin": True, "is_builtin_guest": False, "password_required": True, "password_expires": None, "password_last_set": "2026-03-02T08:11:40Z", "last_logon": None, "user_may_change_pwd": True, "description": "Built-in account for administering the computer/domain"},
                {"name": "Guest", "enabled": False, "is_builtin_admin": False, "is_builtin_guest": True, "password_required": False, "password_expires": None, "password_last_set": None, "last_logon": None, "user_may_change_pwd": False, "description": "Built-in account for guest access to the computer/domain"},
                {"name": "laps-admin", "enabled": True, "is_builtin_admin": False, "is_builtin_guest": False, "password_required": True, "password_expires": "2026-11-10T00:00:00Z", "password_last_set": "2026-10-11T02:00:15Z", "last_logon": "2026-10-14T16:42:03Z", "user_may_change_pwd": True, "description": "Managed by LAPS"},
            ],
            "password_policy": {
                "force_user_logoff_how_long_after_time_expires?": "Never",
                "minimum_password_age_(days)": "1",
                "maximum_password_age_(days)": "365",
                "minimum_password_length": "14",
                "length_of_password_history_maintained": "24",
                "lockout_threshold": "10",
                "lockout_duration_(minutes)": "15",
                "lockout_observation_window_(minutes)": "15",
                "computer_role": "WORKSTATION",
            },
            "summary": {
                "administrators_count": 3,
                "local_admin_members": ["NW-WS-0421\\Administrator", "NW-WS-0421\\laps-admin"],
                "domain_or_entra_members": ["NORTHWIND\\GG-Workstation-Admins"],
                "local_users_total": 3,
                "local_users_enabled": 1,
                "builtin_admin_enabled": False,
                "builtin_guest_enabled": False,
                "enabled_without_password": [],
            },
        }, host, by))

    out.append(example(
        ["ISO27001:A.8.8", "CIS8:7.3", "CIS8:7.4"],
        "windows/Get-PatchStatusEvidence.ps1",
        {
            "operating_system": {"caption": "Microsoft Windows 11 Enterprise", "version": "10.0.26100", "build_number": "26100", "ubr": 4652, "display_version": "24H2", "architecture": "64-bit", "install_date": "2025-02-18T10:05:12Z", "last_boot_utc": "2026-10-13T06:12:44Z", "uptime_days": 2.1},
            "hotfixes": {
                "total_installed": 14,
                "newest_installed_on": "2026-10-09",
                "days_since_newest": 6,
                "items": [
                    {"hotfix_id": "KB5099999", "description": "Security Update", "installed_on": "2026-10-09"},
                    {"hotfix_id": "KB5099001", "description": "Security Update", "installed_on": "2026-09-11"},
                    {"hotfix_id": "KB5098765", "description": "Update", "installed_on": "2026-08-14"},
                ],
            },
            "pending_reboot": {"component_based_servicing": False, "windows_update": False, "pending_file_rename": False, "any": False},
            "update_policy": {"policy_present": True, "no_auto_update": 0, "au_options": 4, "scheduled_install_day": 0, "use_wsus_server": 0, "wsus_server": None, "deferral_quality_days": 7, "deferral_feature_days": 60, "last_install_success_utc": "2026-10-09 03:21:07", "last_detect_success_utc": "2026-10-15 07:02:51"},
            "windows_update_service": {"status": "Running", "start_type": "Manual"},
        }, host, by))

    out.append(example(
        ["ISO27001:A.8.15", "CIS8:8.2", "CIS8:8.3", "CIS8:8.5"],
        "windows/Get-AuditPolicyEvidence.ps1",
        {
            "audit_policy": {
                "subcategory_count": 59,
                "no_auditing_count": 21,
                "settings": [
                    {"subcategory": "Logon", "guid": "{0CCE9215-69AE-11D9-BED3-505054503030}", "setting": "Success and Failure"},
                    {"subcategory": "Logoff", "guid": "{0CCE9216-69AE-11D9-BED3-505054503030}", "setting": "Success"},
                    {"subcategory": "Process Creation", "guid": "{0CCE922B-69AE-11D9-BED3-505054503030}", "setting": "Success"},
                    {"subcategory": "Security Group Management", "guid": "{0CCE9237-69AE-11D9-BED3-505054503030}", "setting": "Success and Failure"},
                    {"subcategory": "Audit Policy Change", "guid": "{0CCE922F-69AE-11D9-BED3-505054503030}", "setting": "Success and Failure"},
                    {"subcategory": "Credential Validation", "guid": "{0CCE923F-69AE-11D9-BED3-505054503030}", "setting": "Success and Failure"},
                    {"subcategory": "Removable Storage", "guid": "{0CCE9245-69AE-11D9-BED3-505054503030}", "setting": "No Auditing"},
                ],
            },
            "event_logs": [
                {"log_name": "Security", "enabled": True, "max_size_mb": 1024.0, "log_mode": "Circular", "record_count": 412233, "oldest_record_utc": None, "file_size_mb": 1024.0},
                {"log_name": "System", "enabled": True, "max_size_mb": 64.0, "log_mode": "Circular", "record_count": 38120, "oldest_record_utc": None, "file_size_mb": 64.0},
                {"log_name": "Microsoft-Windows-PowerShell/Operational", "enabled": True, "max_size_mb": 256.0, "log_mode": "Circular", "record_count": 90412, "oldest_record_utc": None, "file_size_mb": 212.3},
                {"log_name": "Microsoft-Windows-Sysmon/Operational", "enabled": True, "max_size_mb": 512.0, "log_mode": "Circular", "record_count": 301775, "oldest_record_utc": None, "file_size_mb": 498.0},
            ],
            "security_log_span": {"oldest_event_utc": "2026-09-28T14:03:19Z", "days_covered": 16.8},
            "powershell_logging": {"script_block_logging": 1, "module_logging": 1, "transcription": 0, "transcription_dir_set": False},
            "command_line_auditing": {"include_command_line_in_4688": 1},
            "sysmon": {"installed": True, "name": "Sysmon64", "status": "Running"},
        }, host, by))

    out.append(example(
        ["ISO27001:A.8.1", "ISO27001:A.8.24", "CIS8:3.6", "CIS8:3.11"],
        "windows/Get-BitLockerEvidence.ps1",
        {
            "volumes": [
                {"mount_point": "C:", "volume_type": "OperatingSystem", "capacity_gb": 475.7, "protection_status": "On", "volume_status": "FullyEncrypted", "encryption_method": "XtsAes256", "encryption_percentage": 100, "lock_status": "Unlocked", "auto_unlock_enabled": False, "key_protector_types": ["Tpm", "RecoveryPassword"], "recovery_protectors": 1},
                {"mount_point": "D:", "volume_type": "Data", "capacity_gb": 931.5, "protection_status": "On", "volume_status": "FullyEncrypted", "encryption_method": "XtsAes256", "encryption_percentage": 100, "lock_status": "Unlocked", "auto_unlock_enabled": True, "key_protector_types": ["ExternalKey", "RecoveryPassword"], "recovery_protectors": 1},
            ],
            "manage_bde_status": ["BitLocker Drive Encryption: Configuration Tool version 10.0.26100", "Disk volumes that can be protected with", "BitLocker Drive Encryption:", "Volume C: [Windows]", "[OS Volume]", "    Conversion Status:    Fully Encrypted", "    Percentage Encrypted: 100.0%", "    Encryption Method:    XTS-AES 256", "    Protection Status:    Protection On"],
            "tpm": {"present": True, "ready": True, "enabled": True, "activated": True, "owned": True},
            "policy": {"policy_present": True, "os_drive_encryption_method": 7, "fixed_drive_encryption_method": 7, "os_require_tpm": 1, "os_recovery_backup_to_ad": 1, "os_recovery_required_before_enc": 1, "deny_write_unprotected_removable": 1},
            "summary": {"volumes_total": 2, "volumes_protected": 2, "volumes_unprotected": [], "os_drive_protected": True, "os_drive_method": "XtsAes256", "os_drive_has_recovery_key": True},
        }, host, by))

    out.append(example(
        ["ISO27001:A.8.20", "ISO27001:A.8.22", "CIS8:4.4", "CIS8:4.5"],
        "windows/Get-FirewallProfileEvidence.ps1",
        {
            "profiles": [
                {"name": "Domain", "enabled": "True", "default_inbound_action": "Block", "default_outbound_action": "Allow", "allow_inbound_rules": "True", "allow_local_firewall_rules": "False", "notify_on_listen": "False", "log_allowed": "False", "log_blocked": "True", "log_file_name": "%systemroot%\\system32\\LogFiles\\Firewall\\domainfw.log", "log_max_size_kb": 32767},
                {"name": "Private", "enabled": "True", "default_inbound_action": "Block", "default_outbound_action": "Allow", "allow_inbound_rules": "True", "allow_local_firewall_rules": "False", "notify_on_listen": "True", "log_allowed": "False", "log_blocked": "True", "log_file_name": "%systemroot%\\system32\\LogFiles\\Firewall\\privatefw.log", "log_max_size_kb": 32767},
                {"name": "Public", "enabled": "True", "default_inbound_action": "Block", "default_outbound_action": "Allow", "allow_inbound_rules": "True", "allow_local_firewall_rules": "False", "notify_on_listen": "True", "log_allowed": "False", "log_blocked": "True", "log_file_name": "%systemroot%\\system32\\LogFiles\\Firewall\\publicfw.log", "log_max_size_kb": 32767},
            ],
            "rule_summary": {
                "total_rules": 412,
                "by_direction_action_enabled": [
                    {"direction": "Inbound", "action": "Allow", "enabled": "False", "count": 188},
                    {"direction": "Inbound", "action": "Allow", "enabled": "True", "count": 41},
                    {"direction": "Inbound", "action": "Block", "enabled": "True", "count": 6},
                    {"direction": "Outbound", "action": "Allow", "enabled": "False", "count": 102},
                    {"direction": "Outbound", "action": "Allow", "enabled": "True", "count": 75},
                ],
            },
            "enabled_inbound_allow_rules": {
                "count": 41,
                "truncated": False,
                "rules": [
                    {"display_name": "Core Networking - DHCP (DHCP-In)", "profile": "Any", "protocol": "UDP", "local_port": "68", "remote_address": "Any", "policy_store": "PersistentStore"},
                    {"display_name": "Remote Desktop - User Mode (TCP-In)", "profile": "Domain", "protocol": "TCP", "local_port": "3389", "remote_address": "Any", "policy_store": "GroupPolicy"},
                    {"display_name": "EDR Agent Inbound (TCP-In)", "profile": "Domain", "protocol": "TCP", "local_port": "8443", "remote_address": "LocalSubnet", "policy_store": "GroupPolicy"},
                ],
            },
            "service": {"status": "Running", "start_type": "Automatic"},
            "summary": {"all_profiles_enabled": True, "profiles_disabled": [], "profiles_inbound_not_blocked": [], "profiles_without_block_logging": []},
        }, host, by))
    return out


# ----------------------------------------------------------------------------- Linux

def linux_examples() -> list[Path]:
    host, by = "nw-app-07", "root"
    out = []
    out.append(example(
        ["ISO27001:A.8.5", "ISO27001:A.8.9", "ISO27001:A.8.20", "CIS8:3.10", "CIS8:4.1"],
        "linux/ssh-config-evidence.sh",
        {
            "is_root": True,
            "ssh_version": "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024",
            "service": {"active": "active", "enabled": "enabled"},
            "checks": {"permit_root_login": "no", "password_authentication": "no", "pubkey_authentication": "yes", "permit_empty_passwords": "no", "max_auth_tries": "4", "x11_forwarding": "no", "client_alive_interval": "300", "log_level": "VERBOSE", "ciphers": "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr", "macs": "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com", "kex_algorithms": "sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org", "authentication_methods": "publickey", "source": "sshd -T (effective)"},
            "configured_directives": ["/etc/ssh/sshd_config.d/10-northwind.conf:PermitRootLogin no", "/etc/ssh/sshd_config.d/10-northwind.conf:PasswordAuthentication no", "/etc/ssh/sshd_config.d/10-northwind.conf:MaxAuthTries 4", "/etc/ssh/sshd_config.d/10-northwind.conf:X11Forwarding no", "/etc/ssh/sshd_config.d/10-northwind.conf:ClientAliveInterval 300", "/etc/ssh/sshd_config.d/10-northwind.conf:LogLevel VERBOSE", "/etc/ssh/sshd_config.d/10-northwind.conf:AllowGroups ssh-users"],
            "files": [
                {"path": "/etc/ssh/sshd_config", "exists": True, "mode": "600", "owner": "root", "group": "root", "size": 3253, "modified_utc": "2026-06-02T11:20:41Z"},
                {"path": "/etc/ssh/sshd_config.d/10-northwind.conf", "exists": True, "mode": "600", "owner": "root", "group": "root", "size": 212, "modified_utc": "2026-06-02T11:20:41Z"},
                {"path": "/etc/ssh/ssh_host_ed25519_key", "exists": True, "mode": "600", "owner": "root", "group": "root", "size": 411, "modified_utc": "2025-02-18T10:07:03Z"},
                {"path": "/etc/ssh/ssh_host_ed25519_key.pub", "exists": True, "mode": "644", "owner": "root", "group": "root", "size": 96, "modified_utc": "2025-02-18T10:07:03Z"},
            ],
            "effective_configuration": {"command": "sshd -T", "exit_code": 0, "stdout": "port 22\naddressfamily any\nlistenaddress [::]:22\nlistenaddress 0.0.0.0:22\npermitrootlogin no\npasswordauthentication no\npubkeyauthentication yes\nmaxauthtries 4\nx11forwarding no\nclientaliveinterval 300\nloglevel VERBOSE\nallowgroups ssh-users", "stderr": ""},
        }, host, by))

    out.append(example(
        ["ISO27001:A.8.8", "CIS8:7.3", "CIS8:7.4"],
        "linux/patch-status-evidence.sh",
        {
            "is_root": True,
            "distribution": "Ubuntu 24.04.2 LTS",
            "os_release": ["PRETTY_NAME=\"Ubuntu 24.04.2 LTS\"", "NAME=\"Ubuntu\"", "VERSION_ID=\"24.04\"", "ID=ubuntu", "ID_LIKE=debian"],
            "kernel": {"running": "6.8.0-45-generic", "newest_installed": "6.8.0-45-generic", "running_is_newest": True},
            "uptime_days": 11.4,
            "package_manager": "apt",
            "pending_updates": {"count": 3, "security_count": 2, "packages": ["libssl3t64/noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]", "openssl/noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]", "vim-common/noble-updates 2:9.1.0016-1ubuntu7.6 all [upgradable from: 2:9.1.0016-1ubuntu7.5]"]},
            "last_update_run": "2026-10-15T06:17:02Z",
            "reboot_required": False,
            "automatic_updates": {"unattended_upgrades_installed": True, "apt_periodic_config": ["APT::Periodic::Update-Package-Lists \"1\";", "APT::Periodic::Unattended-Upgrade \"1\";"], "last_history_entry": "2026-10-12  06:20:14"},
        }, host, by))

    out.append(example(
        ["ISO27001:A.8.15", "ISO27001:A.8.16", "CIS8:8.2", "CIS8:8.5", "CIS8:8.9"],
        "linux/auditd-evidence.sh",
        {
            "is_root": True,
            "service": {"installed": True, "active": "active", "enabled": "enabled"},
            "audit_status": {"command": "auditctl -s", "exit_code": 0, "stdout": "enabled 2\nfailure 1\npid 812\nrate_limit 0\nbacklog_limit 8192\nlost 0\nbacklog 0\nbacklog_wait_time 60000\nbacklog_wait_time_actual 0\nloginuid_immutable 0 unlocked", "stderr": ""},
            "loaded_rules": {"command": "auditctl -l", "exit_code": 0, "stdout": "-w /etc/sudoers -p wa -k scope\n-w /etc/sudoers.d -p wa -k scope\n-w /etc/passwd -p wa -k identity\n-w /etc/shadow -p wa -k identity\n-a always,exit -F arch=b64 -S execve -F euid=0 -k rootcmd\n-w /var/log/sudo.log -p wa -k actions\n-e 2", "stderr": ""},
            "rules_files": [
                {"path": "/etc/audit/rules.d/10-base.rules", "readable": True, "sha256": "4d1f0c9d2e5b7a8f6c3e1a9b8d7c6f5e4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d", "active_lines": 4},
                {"path": "/etc/audit/rules.d/50-northwind.rules", "readable": True, "sha256": "9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c", "active_lines": 7},
                {"path": "/etc/audit/rules.d/99-finalize.rules", "readable": True, "sha256": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b", "active_lines": 1},
            ],
            "auditd_conf": {"readable": True, "log_file": "/var/log/audit/audit.log", "log_format": "ENRICHED", "max_log_file_mb": 50, "num_logs": 10, "max_log_file_action": "ROTATE", "space_left_action": "SYSLOG", "admin_space_left_action": "SUSPEND", "disk_full_action": "SUSPEND", "disk_error_action": "SUSPEND", "flush": "INCREMENTAL_ASYNC"},
            "audit_log_file": {"path": "/var/log/audit/audit.log", "exists": True, "mode": "600", "owner": "root", "group": "root", "size": 23891244, "modified_utc": "2026-10-15T09:29:58Z"},
            "journald": {"settings": ["Storage=persistent", "SystemMaxUse=2G"], "persistent_dir_exists": True},
            "remote_forwarding": ["/etc/rsyslog.d/60-forward.conf:*.* @@siem-collector.northwind.example:6514"],
        }, host, by))

    out.append(example(
        ["ISO27001:A.5.15", "ISO27001:A.5.16", "ISO27001:A.5.18", "ISO27001:A.8.2", "CIS8:5.1", "CIS8:5.2", "CIS8:5.4"],
        "linux/users-sudoers-evidence.sh",
        {
            "is_root": True,
            "login_accounts": [
                {"name": "root", "uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash", "password_state": "locked", "password_age_days": None, "password_max_days": 99999},
                {"name": "ops-admin", "uid": 1001, "gid": 1001, "home": "/home/ops-admin", "shell": "/bin/bash", "password_state": "set", "password_age_days": 42, "password_max_days": 365},
                {"name": "deploy", "uid": 1002, "gid": 1002, "home": "/home/deploy", "shell": "/bin/bash", "password_state": "locked", "password_age_days": None, "password_max_days": 99999},
            ],
            "uid_zero_accounts": ["root"],
            "privileged_groups": [
                {"group": "sudo", "members": ["ops-admin"]},
                {"group": "adm", "members": ["syslog", "ops-admin"]},
                {"group": "root", "members": []},
            ],
            "login_defs": {"pass_max_days": 365, "pass_min_days": 1, "pass_warn_age": 14, "encrypt_method": "YESCRYPT", "umask": "027"},
            "sudoers": {
                "readable": True,
                "sudo_version": "Sudo version 1.9.15p5",
                "nopasswd_entries": 1,
                "unrestricted_all_entries": 1,
                "active_lines": ["/etc/sudoers:Defaults\tenv_reset", "/etc/sudoers:Defaults\tuse_pty", "/etc/sudoers:Defaults\tlogfile=\"/var/log/sudo.log\"", "/etc/sudoers:root\tALL=(ALL:ALL) ALL", "/etc/sudoers:%sudo\tALL=(ALL:ALL) ALL", "/etc/sudoers:@includedir /etc/sudoers.d", "/etc/sudoers.d/90-deploy:deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart northwind-api.service"],
            },
        }, host, by))
    return out


# ----------------------------------------------------------------------------- Microsoft 365

def m365_examples() -> list[Path]:
    host, by = f"entra-tenant:{TENANT}", "evidence.reader@northwind.example"
    out = []
    out.append(example(
        ["ISO27001:A.5.17", "ISO27001:A.8.5", "CIS8:6.3", "CIS8:6.5"],
        "m365/Get-MfaRegistrationEvidence.ps1",
        {
            "tenant_id": TENANT,
            "scopes_used": ["AuditLog.Read.All", "UserAuthenticationMethod.Read.All"],
            "auth_type": "Delegated",
            "registration": {
                "users_total": 842, "members_total": 790, "guests_total": 52,
                "mfa_registered": 801, "mfa_capable": 805,
                "members_mfa_registered": 781, "members_mfa_registered_pct": 98.9,
                "passwordless_capable": 312, "sspr_registered": 744, "sspr_capable": 760,
                "system_preferred_enabled": 842,
                "admins_total": 14, "admins_mfa_registered": 14, "admins_without_mfa": 0,
                "methods_registered_counts": {"microsoftAuthenticatorPush": 731, "softwareOneTimePasscode": 119, "mobilePhone": 402, "windowsHelloForBusiness": 298, "passKeyDeviceBound": 41, "email": 610, "temporaryAccessPass": 3},
                "default_mfa_method_counts": {"microsoftAuthenticatorPush": 702, "mobilePhone": 88, "softwareOneTimePasscode": 11, "none": 41},
            },
        }, host, by))

    out.append(example(
        ["ISO27001:A.5.15", "ISO27001:A.8.3", "ISO27001:A.8.5", "CIS8:6.3", "CIS8:6.4", "CIS8:6.5"],
        "m365/Get-ConditionalAccessEvidence.ps1",
        {
            "tenant_id": TENANT,
            "scopes_used": ["Policy.Read.All"],
            "policies": [
                {"id": "0a1b2c3d-0001-4000-8000-000000000001", "display_name": "CA001 - Require MFA for all users", "state": "enabled", "created_utc": "2025-03-04T09:12:00Z", "modified_utc": "2026-07-22T14:40:11Z",
                 "users": {"include_all": True, "include_users_count": 0, "include_groups_count": 0, "include_roles_count": 0, "include_guests": False, "exclude_users_count": 2, "exclude_groups_count": 1, "exclude_roles_count": 0},
                 "applications": {"include_all": True, "include_count": 1, "exclude_count": 0, "user_actions": []},
                 "client_app_types": ["all"], "platforms_included": [], "locations_included": [], "locations_excluded": [], "sign_in_risk_levels": [], "user_risk_levels": [], "device_filter": None,
                 "grant": {"operator": "OR", "built_in_controls": ["mfa"], "authentication_strength": None, "terms_of_use_count": 0},
                 "session": {"sign_in_frequency": None, "persistent_browser": None, "app_enforced_restrictions": False, "cloud_app_security": None}},
                {"id": "0a1b2c3d-0002-4000-8000-000000000002", "display_name": "CA002 - Block legacy authentication", "state": "enabled", "created_utc": "2025-03-04T09:15:00Z", "modified_utc": "2025-03-04T09:15:00Z",
                 "users": {"include_all": True, "include_users_count": 0, "include_groups_count": 0, "include_roles_count": 0, "include_guests": False, "exclude_users_count": 0, "exclude_groups_count": 0, "exclude_roles_count": 0},
                 "applications": {"include_all": True, "include_count": 1, "exclude_count": 0, "user_actions": []},
                 "client_app_types": ["exchangeActiveSync", "other"], "platforms_included": [], "locations_included": [], "locations_excluded": [], "sign_in_risk_levels": [], "user_risk_levels": [], "device_filter": None,
                 "grant": {"operator": "OR", "built_in_controls": ["block"], "authentication_strength": None, "terms_of_use_count": 0},
                 "session": {"sign_in_frequency": None, "persistent_browser": None, "app_enforced_restrictions": False, "cloud_app_security": None}},
                {"id": "0a1b2c3d-0003-4000-8000-000000000003", "display_name": "CA003 - Phishing-resistant MFA for admin roles", "state": "enabled", "created_utc": "2026-01-19T10:00:00Z", "modified_utc": "2026-01-19T10:00:00Z",
                 "users": {"include_all": False, "include_users_count": 0, "include_groups_count": 0, "include_roles_count": 14, "include_guests": False, "exclude_users_count": 2, "exclude_groups_count": 0, "exclude_roles_count": 0},
                 "applications": {"include_all": True, "include_count": 1, "exclude_count": 0, "user_actions": []},
                 "client_app_types": ["all"], "platforms_included": [], "locations_included": [], "locations_excluded": [], "sign_in_risk_levels": [], "user_risk_levels": [], "device_filter": None,
                 "grant": {"operator": "OR", "built_in_controls": [], "authentication_strength": "Phishing-resistant MFA", "terms_of_use_count": 0},
                 "session": {"sign_in_frequency": "4 hours", "persistent_browser": "never", "app_enforced_restrictions": False, "cloud_app_security": None}},
                {"id": "0a1b2c3d-0004-4000-8000-000000000004", "display_name": "CA004 - Block high sign-in risk", "state": "enabled", "created_utc": "2026-02-02T08:30:00Z", "modified_utc": "2026-02-02T08:30:00Z",
                 "users": {"include_all": True, "include_users_count": 0, "include_groups_count": 0, "include_roles_count": 0, "include_guests": False, "exclude_users_count": 2, "exclude_groups_count": 0, "exclude_roles_count": 0},
                 "applications": {"include_all": True, "include_count": 1, "exclude_count": 0, "user_actions": []},
                 "client_app_types": ["all"], "platforms_included": [], "locations_included": [], "locations_excluded": [], "sign_in_risk_levels": ["high"], "user_risk_levels": [], "device_filter": None,
                 "grant": {"operator": "OR", "built_in_controls": ["block"], "authentication_strength": None, "terms_of_use_count": 0},
                 "session": {"sign_in_frequency": None, "persistent_browser": None, "app_enforced_restrictions": False, "cloud_app_security": None}},
                {"id": "0a1b2c3d-0005-4000-8000-000000000005", "display_name": "CA005 - Require compliant device for Office 365 (report-only)", "state": "enabledForReportingButNotEnforced", "created_utc": "2026-09-10T15:00:00Z", "modified_utc": "2026-09-10T15:00:00Z",
                 "users": {"include_all": True, "include_users_count": 0, "include_groups_count": 0, "include_roles_count": 0, "include_guests": False, "exclude_users_count": 2, "exclude_groups_count": 1, "exclude_roles_count": 0},
                 "applications": {"include_all": False, "include_count": 1, "exclude_count": 0, "user_actions": []},
                 "client_app_types": ["all"], "platforms_included": ["windows", "macOS"], "locations_included": [], "locations_excluded": [], "sign_in_risk_levels": [], "user_risk_levels": [], "device_filter": None,
                 "grant": {"operator": "OR", "built_in_controls": ["compliantDevice"], "authentication_strength": None, "terms_of_use_count": 0},
                 "session": {"sign_in_frequency": None, "persistent_browser": None, "app_enforced_restrictions": False, "cloud_app_security": None}},
            ],
            "named_locations": [
                {"display_name": "Northwind offices", "type": "ipNamedLocation", "is_trusted": True, "ip_ranges": 3, "countries": None},
                {"display_name": "Blocked countries", "type": "countryNamedLocation", "is_trusted": None, "ip_ranges": None, "countries": 12},
            ],
            "checks": {"policies_total": 5, "policies_enabled": 4, "policies_report_only": 1, "policies_disabled": 0, "mfa_for_all_users": True, "mfa_for_admin_roles": True, "legacy_auth_blocked": True, "sign_in_risk_policy": True, "user_risk_policy": False, "device_compliance_required": False, "guest_specific_policy": False, "policies_with_exclusions": 3, "enabled_policy_names": ["CA001 - Require MFA for all users", "CA002 - Block legacy authentication", "CA003 - Phishing-resistant MFA for admin roles", "CA004 - Block high sign-in risk"]},
        }, host, by))

    out.append(example(
        ["ISO27001:A.5.16", "ISO27001:A.5.18", "ISO27001:A.5.19", "CIS8:5.1", "CIS8:5.3", "CIS8:6.1"],
        "m365/Get-GuestInventoryEvidence.ps1",
        {
            "tenant_id": TENANT,
            "scopes_used": ["AuditLog.Read.All", "Policy.Read.All", "User.Read.All"],
            "inactive_days": 90,
            "guests": {
                "sign_in_activity_available": True,
                "total": 52, "enabled": 47, "disabled": 5, "pending_acceptance": 4,
                "created_last_30_days": 3, "inactive_over_threshold": 11, "never_signed_in": 4,
                "home_domains": 6,
                "guests_per_home_domain": {"contoso.example": 23, "fabrikam.example": 14, "auditpartners.example": 6, "gmail.example": 5, "tailspin.example": 3, "unknown": 1},
            },
            "external_collaboration": {"allow_invites_from": "adminsAndGuestInviters", "guest_user_role_id": "2af84b1e-32c8-42b7-82bc-daa82404023b", "allow_email_verified_users_to_join": False, "block_msol_powershell": True},
        }, host, by))
    return out


# ----------------------------------------------------------------------------- Cloud

def cloud_examples() -> list[Path]:
    out = []
    out.append(example(
        ["ISO27001:A.5.23", "ISO27001:A.8.3", "ISO27001:A.8.24", "CIS8:3.3", "CIS8:3.11", "CIS8:8.5"],
        "cloud/aws_s3_public_access.py",
        {
            "account_id": AWS_ACCOUNT,
            "caller_arn": f"arn:aws:sts::{AWS_ACCOUNT}:assumed-role/SecurityAudit/evidence.reader",
            "account_public_access_block": {"block_public_acls": True, "ignore_public_acls": True, "block_public_policy": True, "restrict_public_buckets": True},
            "buckets_total": 4,
            "buckets_truncated": False,
            "buckets": [
                {"name": "northwind-app-logs-eu", "region": "eu-west-1", "public_access_block": {"block_public_acls": True, "ignore_public_acls": True, "block_public_policy": True, "restrict_public_buckets": True}, "policy_is_public": False, "acl_public_grants": [], "acl_is_public": False, "default_encryption": {"algorithm": "aws:kms", "kms_key_configured": True, "bucket_key_enabled": True}, "versioning": "Enabled", "access_logging": {"enabled": True, "target_bucket": "northwind-s3-access-logs"}},
                {"name": "northwind-backups-eu", "region": "eu-west-1", "public_access_block": {"block_public_acls": True, "ignore_public_acls": True, "block_public_policy": True, "restrict_public_buckets": True}, "policy_is_public": False, "acl_public_grants": [], "acl_is_public": False, "default_encryption": {"algorithm": "aws:kms", "kms_key_configured": True, "bucket_key_enabled": True}, "versioning": "Enabled", "access_logging": {"enabled": True, "target_bucket": "northwind-s3-access-logs"}},
                {"name": "northwind-marketing-site", "region": "us-east-1", "public_access_block": {"block_public_acls": True, "ignore_public_acls": True, "block_public_policy": False, "restrict_public_buckets": False}, "policy_is_public": True, "acl_public_grants": [], "acl_is_public": False, "default_encryption": {"algorithm": "AES256", "kms_key_configured": False, "bucket_key_enabled": False}, "versioning": "Disabled", "access_logging": {"enabled": False}},
                {"name": "northwind-s3-access-logs", "region": "eu-west-1", "public_access_block": {"block_public_acls": True, "ignore_public_acls": True, "block_public_policy": True, "restrict_public_buckets": True}, "policy_is_public": False, "acl_public_grants": [], "acl_is_public": False, "default_encryption": {"algorithm": "AES256", "kms_key_configured": False, "bucket_key_enabled": False}, "versioning": "Disabled", "access_logging": {"enabled": False}},
            ],
            "summary": {
                "account_block_is_full": True,
                "buckets_public_by_policy": ["northwind-marketing-site"],
                "buckets_public_by_acl": [],
                "buckets_without_full_block": ["northwind-marketing-site"],
                "buckets_without_default_encryption": [],
                "buckets_without_access_logging": ["northwind-marketing-site", "northwind-s3-access-logs"],
                "buckets_with_versioning": 2,
            },
        }, f"aws-account:{AWS_ACCOUNT}", f"arn:aws:sts::{AWS_ACCOUNT}:assumed-role/SecurityAudit/evidence.reader"))

    out.append(example(
        ["ISO27001:A.5.23", "ISO27001:A.8.20", "ISO27001:A.8.24", "CIS8:3.3", "CIS8:3.10", "CIS8:3.11"],
        "cloud/azure_storage_encryption.py",
        {
            "subscriptions_total": 1,
            "subscriptions": [
                {"subscription_id": SUBSCRIPTION, "display_name": "Northwind Production", "storage_accounts": [
                    {"name": "nwprodappdata01", "resource_group": "rg-prod-app", "location": "westeurope", "sku": "Standard_ZRS", "kind": "StorageV2", "created_utc": "2025-04-11T13:02:45Z",
                     "encryption": {"key_source": "Microsoft.Keyvault", "customer_managed_key": True, "require_infrastructure_encryption": True, "blob": {"enabled": True, "key_type": "Account"}, "file": {"enabled": True, "key_type": "Account"}, "table": None, "queue": None},
                     "https_traffic_only": True, "minimum_tls_version": "TLS1_2", "allow_blob_public_access": False, "allow_shared_key_access": False, "public_network_access": "Disabled", "network_default_action": "Deny", "network_ip_rules": 0, "network_vnet_rules": 2, "private_endpoints": 1, "allow_cross_tenant_replication": False},
                    {"name": "nwproddiag01", "resource_group": "rg-prod-monitoring", "location": "westeurope", "sku": "Standard_LRS", "kind": "StorageV2", "created_utc": "2025-04-11T13:10:02Z",
                     "encryption": {"key_source": "Microsoft.Storage", "customer_managed_key": False, "require_infrastructure_encryption": False, "blob": {"enabled": True, "key_type": "Account"}, "file": {"enabled": True, "key_type": "Account"}, "table": None, "queue": None},
                     "https_traffic_only": True, "minimum_tls_version": "TLS1_2", "allow_blob_public_access": False, "allow_shared_key_access": True, "public_network_access": "Enabled", "network_default_action": "Allow", "network_ip_rules": 0, "network_vnet_rules": 0, "private_endpoints": 0, "allow_cross_tenant_replication": False},
                    {"name": "nwlegacyweb", "resource_group": "rg-legacy", "location": "northeurope", "sku": "Standard_LRS", "kind": "Storage", "created_utc": "2021-09-30T08:44:19Z",
                     "encryption": {"key_source": "Microsoft.Storage", "customer_managed_key": False, "require_infrastructure_encryption": False, "blob": {"enabled": True, "key_type": "Account"}, "file": {"enabled": True, "key_type": "Account"}, "table": None, "queue": None},
                     "https_traffic_only": False, "minimum_tls_version": "TLS1_0", "allow_blob_public_access": True, "allow_shared_key_access": True, "public_network_access": "Enabled", "network_default_action": "Allow", "network_ip_rules": 0, "network_vnet_rules": 0, "private_endpoints": 0, "allow_cross_tenant_replication": True},
                ]},
            ],
            "summary": {
                "storage_accounts_total": 3,
                "customer_managed_key": 1,
                "infrastructure_encryption": 1,
                "accounts_allowing_http": ["nwlegacyweb"],
                "accounts_tls_below_1_2": ["nwlegacyweb"],
                "accounts_allowing_public_blob_access": ["nwlegacyweb"],
                "accounts_allowing_shared_key": ["nwproddiag01", "nwlegacyweb"],
                "accounts_network_default_allow": ["nwproddiag01", "nwlegacyweb"],
            },
        }, f"azure-subscription:{SUBSCRIPTION}", "evidence.reader@northwind.example"))
    return out


def main() -> int:
    if EXAMPLES.exists():
        shutil.rmtree(EXAMPLES)
    EXAMPLES.mkdir(parents=True)
    written = windows_examples() + linux_examples() + m365_examples() + cloud_examples()
    for p in written:
        print(f"wrote examples/{p.name}")
    print(f"{len(written)} example files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
