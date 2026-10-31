#!/usr/bin/env bash
# ssh-config-evidence.sh - SSH daemon hardening evidence for a Linux host.
#
# Read-only. Records the effective sshd settings (sshd -T, root only), the security-relevant directives
# found in /etc/ssh/sshd_config and sshd_config.d/*.conf, permissions of the config and host keys,
# the sshd service state and version, then writes a hashed JSON envelope.
#
# Controls : ISO27001:A.8.5, ISO27001:A.8.9, ISO27001:A.8.20 | CIS8:3.10, CIS8:4.1
# Requires : bash 4+, coreutils. Run as root for "sshd -T"; a normal user still gets the file-based view.
# Usage    : ./ssh-config-evidence.sh [output-dir]
# Author   : Wassim Bizid - MIT License - https://github.com/bizidwassim-design/control-evidence-collector
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../lib/evidence.sh
source "$SCRIPT_DIR/../../lib/evidence.sh"

OUT_DIR="${1:-./evidence}"
CONFIG="/etc/ssh/sshd_config"
DIRECTIVES='PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|PermitEmptyPasswords|ChallengeResponseAuthentication|KbdInteractiveAuthentication|MaxAuthTries|MaxSessions|X11Forwarding|AllowTcpForwarding|ClientAliveInterval|ClientAliveCountMax|LoginGraceTime|AllowUsers|AllowGroups|DenyUsers|DenyGroups|Ciphers|MACs|KexAlgorithms|HostKeyAlgorithms|LogLevel|UsePAM|Banner|Protocol|Port|ListenAddress|AuthenticationMethods|PermitUserEnvironment|IgnoreRhosts|HostbasedAuthentication|StrictModes'

# Effective configuration (sshd -T needs root and a valid config)
if command -v sshd >/dev/null 2>&1; then
  effective=$(evidence_command sshd -T)
else
  effective=$(evidence_object "error" "$(evidence_string "sshd binary not found")")
fi

# Security-relevant directives from the main file and drop-ins, in file order (first match wins in sshd)
configured_directives() {
  local f
  for f in "$CONFIG" /etc/ssh/sshd_config.d/*.conf; do
    [ -r "$f" ] || continue
    grep -EiH "^[[:space:]]*(${DIRECTIVES})[[:space:]]" "$f" 2>/dev/null | sed 's/[[:space:]]\+/ /g'
  done
}
directives_json=$(configured_directives | evidence_lines_array)

# Quick checks an auditor usually asks for, derived from "sshd -T" when available, else from the files
effective_value() {
  # $1 = directive (lowercase as printed by sshd -T)
  if command -v sshd >/dev/null 2>&1; then
    sshd -T 2>/dev/null | awk -v k="$1" '$1 == k { $1 = ""; sub(/^ /, ""); print; exit }'
  fi
}
file_value() {
  configured_directives | grep -Ei ":[[:space:]]*$1[[:space:]]" | head -n 1 | awk '{ $1 = ""; sub(/^ /, ""); print }'
}
pick() {
  local v
  v=$(effective_value "$1")
  if [ -n "$v" ]; then printf '%s' "$v"; else file_value "$1"; fi
}

checks=$(evidence_object \
  "permit_root_login" "$(evidence_string "$(pick permitrootlogin)")" \
  "password_authentication" "$(evidence_string "$(pick passwordauthentication)")" \
  "pubkey_authentication" "$(evidence_string "$(pick pubkeyauthentication)")" \
  "permit_empty_passwords" "$(evidence_string "$(pick permitemptypasswords)")" \
  "max_auth_tries" "$(evidence_string "$(pick maxauthtries)")" \
  "x11_forwarding" "$(evidence_string "$(pick x11forwarding)")" \
  "client_alive_interval" "$(evidence_string "$(pick clientaliveinterval)")" \
  "log_level" "$(evidence_string "$(pick loglevel)")" \
  "ciphers" "$(evidence_string "$(pick ciphers)")" \
  "macs" "$(evidence_string "$(pick macs)")" \
  "kex_algorithms" "$(evidence_string "$(pick kexalgorithms)")" \
  "authentication_methods" "$(evidence_string "$(pick authenticationmethods)")" \
  "source" "$(evidence_string "$(if [ "$(evidence_is_root)" = "true" ] && command -v sshd >/dev/null 2>&1; then echo "sshd -T (effective)"; else echo "configuration files (not effective: run as root for sshd -T)"; fi)")")

# File permissions of the config and host keys
files_json="["
first=1
for f in "$CONFIG" /etc/ssh/sshd_config.d/*.conf /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub; do
  [ -e "$f" ] || continue
  if [ $first -eq 1 ]; then first=0; else files_json+=","; fi
  files_json+=$'\n'"$(evidence_file_stat "$f")"
done
files_json+=$'\n]'

# Service and version
service_state=$(systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null || echo "unknown")
service_enabled=$(systemctl is-enabled sshd 2>/dev/null || systemctl is-enabled ssh 2>/dev/null || echo "unknown")
version=$(ssh -V 2>&1 | head -n 1)

data=$(evidence_object \
  "is_root" "$(evidence_is_root)" \
  "ssh_version" "$(evidence_string "$version")" \
  "service" "$(evidence_object "active" "$(evidence_string "$service_state")" "enabled" "$(evidence_string "$service_enabled")")" \
  "checks" "$checks" \
  "configured_directives" "$directives_json" \
  "files" "$files_json" \
  "effective_configuration" "$effective")

file=$(evidence_write "ISO27001:A.8.5,ISO27001:A.8.9,ISO27001:A.8.20,CIS8:3.10,CIS8:4.1" \
  "linux/ssh-config-evidence.sh" "$data" "$OUT_DIR") || exit 1
echo "Evidence written: $file"
evidence_verify "$file" >/dev/null && echo "SHA-256 verified."
