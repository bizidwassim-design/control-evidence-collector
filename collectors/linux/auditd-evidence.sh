#!/usr/bin/env bash
# auditd-evidence.sh - Audit logging evidence for a Linux host (auditd, journald, rsyslog forwarding).
#
# Read-only. Records the auditd service state, loaded audit rules (root), the rules files with their
# SHA-256, key auditd.conf settings (log size, rotation, disk-full behaviour), journald persistence and
# any remote syslog forwarding targets, then writes a hashed JSON envelope.
#
# Controls : ISO27001:A.8.15, ISO27001:A.8.16 | CIS8:8.2, CIS8:8.5, CIS8:8.9
# Requires : bash 4+, coreutils. Root for auditctl and /etc/audit; otherwise the error is recorded.
# Usage    : ./auditd-evidence.sh [output-dir]
# Author   : Wassim Bizid - MIT License - https://github.com/bizidwassim-design/control-evidence-collector
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../lib/evidence.sh
source "$SCRIPT_DIR/../../lib/evidence.sh"

OUT_DIR="${1:-./evidence}"

# Service state
svc_active=$(systemctl is-active auditd 2>/dev/null || echo "unknown")
svc_enabled=$(systemctl is-enabled auditd 2>/dev/null || echo "unknown")
service_json=$(evidence_object \
  "installed" "$(if command -v auditctl >/dev/null 2>&1 || [ -x /sbin/auditd ]; then echo true; else echo false; fi)" \
  "active" "$(evidence_string "$svc_active")" \
  "enabled" "$(evidence_string "$svc_enabled")")

# Loaded rules and kernel audit status (root)
if command -v auditctl >/dev/null 2>&1; then
  status_json=$(evidence_command auditctl -s)
  rules_cmd=$(evidence_command auditctl -l)
else
  status_json=$(evidence_object "error" "$(evidence_string "auditctl not found")")
  rules_cmd="$status_json"
fi

# Rules files with a hash of each, so an auditor can match them to a baseline
rules_files="["
first=1
for f in /etc/audit/audit.rules /etc/audit/rules.d/*.rules; do
  [ -e "$f" ] || continue
  if [ $first -eq 1 ]; then first=0; else rules_files+=","; fi
  if [ -r "$f" ]; then
    h=$(evidence_sha256_stdin < "$f")
    n=$(grep -Ev '^\s*(#|$)' "$f" | grep -c . || true)
  else
    h=""; n="null"
  fi
  rules_files+=$'\n'"$(evidence_object \
    "path" "$(evidence_string "$f")" \
    "readable" "$(if [ -r "$f" ]; then echo true; else echo false; fi)" \
    "sha256" "$(evidence_string "$h")" \
    "active_lines" "$(evidence_number "$n")")"
done
rules_files+=$'\n]'

# auditd.conf settings that matter for retention and fail-safe behaviour
conf="/etc/audit/auditd.conf"
conf_value() { grep -Ei "^\s*$1\s*=" "$conf" 2>/dev/null | head -n 1 | cut -d= -f2- | sed 's/^\s*//; s/\s*$//'; }
auditd_conf=$(evidence_object \
  "readable" "$(if [ -r "$conf" ]; then echo true; else echo false; fi)" \
  "log_file" "$(evidence_string "$(conf_value log_file)")" \
  "log_format" "$(evidence_string "$(conf_value log_format)")" \
  "max_log_file_mb" "$(evidence_number "$(conf_value max_log_file)")" \
  "num_logs" "$(evidence_number "$(conf_value num_logs)")" \
  "max_log_file_action" "$(evidence_string "$(conf_value max_log_file_action)")" \
  "space_left_action" "$(evidence_string "$(conf_value space_left_action)")" \
  "admin_space_left_action" "$(evidence_string "$(conf_value admin_space_left_action)")" \
  "disk_full_action" "$(evidence_string "$(conf_value disk_full_action)")" \
  "disk_error_action" "$(evidence_string "$(conf_value disk_error_action)")" \
  "flush" "$(evidence_string "$(conf_value flush)")")

# Current audit log file size and age
log_path=$(conf_value log_file); log_path="${log_path:-/var/log/audit/audit.log}"
audit_log=$(evidence_file_stat "$log_path")

# journald persistence and limits
journald_lines() {
  local f
  for f in /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf; do
    [ -r "$f" ] || continue
    grep -E '^\s*(Storage|SystemMaxUse|SystemKeepFree|MaxRetentionSec|ForwardToSyslog)\s*=' "$f" 2>/dev/null
  done
}
journald=$(evidence_object \
  "settings" "$(journald_lines | evidence_lines_array)" \
  "persistent_dir_exists" "$(if [ -d /var/log/journal ]; then echo true; else echo false; fi)")

# Remote syslog forwarding (rsyslog "@host" / "@@host", omfwd, syslog-ng destinations)
forwarding() {
  local f
  for f in /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog-ng/syslog-ng.conf /etc/syslog-ng/conf.d/*.conf; do
    [ -r "$f" ] || continue
    grep -EH '^\s*[^#].*(@@?[A-Za-z0-9\[]|omfwd|target\(|destination\s+d_)' "$f" 2>/dev/null
  done
}
forward_json=$(forwarding | evidence_lines_array)

data=$(evidence_object \
  "is_root" "$(evidence_is_root)" \
  "service" "$service_json" \
  "audit_status" "$status_json" \
  "loaded_rules" "$rules_cmd" \
  "rules_files" "$rules_files" \
  "auditd_conf" "$auditd_conf" \
  "audit_log_file" "$audit_log" \
  "journald" "$journald" \
  "remote_forwarding" "$forward_json")

file=$(evidence_write "ISO27001:A.8.15,ISO27001:A.8.16,CIS8:8.2,CIS8:8.5,CIS8:8.9" "linux/auditd-evidence.sh" "$data" "$OUT_DIR") || exit 1
echo "Evidence written: $file"
evidence_verify "$file" >/dev/null && echo "SHA-256 verified."
