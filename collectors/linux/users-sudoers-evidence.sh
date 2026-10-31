#!/usr/bin/env bash
# users-sudoers-evidence.sh - Local accounts, privileged groups and sudo configuration evidence.
#
# Read-only. Records every account with a login shell (UID, shell, locked state and password age taken
# from /etc/shadow when root - never the hashes), accounts with UID 0, members of sudo/wheel/admin
# groups, password-ageing defaults from /etc/login.defs and the active lines of /etc/sudoers and
# /etc/sudoers.d (with a count of NOPASSWD entries), then writes a hashed JSON envelope.
#
# Controls : ISO27001:A.5.15, ISO27001:A.5.16, ISO27001:A.5.18, ISO27001:A.8.2 | CIS8:5.1, CIS8:5.2, CIS8:5.4
# Requires : bash 4+, coreutils, getent. Root to read /etc/shadow and sudoers; otherwise those fields are null.
# Usage    : ./users-sudoers-evidence.sh [output-dir]
# Author   : Wassim Bizid - MIT License - https://github.com/bizidwassim-design/control-evidence-collector
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../lib/evidence.sh
source "$SCRIPT_DIR/../../lib/evidence.sh"

OUT_DIR="${1:-./evidence}"
is_root=$(evidence_is_root)
today_days=$(( $(date -u +%s) / 86400 ))

# Shadow lookups (root only). Field 2 = hash (never exported), 3 = last change (days), 5 = max days.
shadow_field() {
  # $1 = user, $2 = field number
  [ "$is_root" = "true" ] && [ -r /etc/shadow ] || return 0
  awk -F: -v u="$1" -v f="$2" '$1 == u { print $f; exit }' /etc/shadow
}
password_state() {
  # prints: locked|no_password|set|unknown
  local h; h=$(shadow_field "$1" 2)
  if [ "$is_root" != "true" ]; then printf 'unknown'
  elif [ -z "$h" ]; then printf 'no_password'
  elif [[ "$h" == '!'* || "$h" == '*'* ]]; then printf 'locked'
  else printf 'set'; fi
}

# Accounts with a real login shell
accounts="["
first=1
while IFS=: read -r name _ uid gid _ home shell; do
  case "$shell" in */nologin|*/false|"") continue ;; esac
  if [ $first -eq 1 ]; then first=0; else accounts+=","; fi
  last_change=$(shadow_field "$name" 3); max_days=$(shadow_field "$name" 5)
  age="null"
  if [ -n "$last_change" ] && [ "$last_change" -gt 0 ] 2>/dev/null; then age=$(( today_days - last_change )); fi
  accounts+=$'\n'"$(evidence_object \
    "name" "$(evidence_string "$name")" \
    "uid" "$(evidence_number "$uid")" \
    "gid" "$(evidence_number "$gid")" \
    "home" "$(evidence_string "$home")" \
    "shell" "$(evidence_string "$shell")" \
    "password_state" "$(evidence_string "$(password_state "$name")")" \
    "password_age_days" "$(evidence_number "$age")" \
    "password_max_days" "$(evidence_number "${max_days:-}")")"
done < <(getent passwd 2>/dev/null || cat /etc/passwd 2>/dev/null)
accounts+=$'\n]'

uid0=$( (getent passwd 2>/dev/null || cat /etc/passwd 2>/dev/null) | awk -F: '$3 == 0 { print $1 }' | evidence_lines_array)

# Privileged groups
groups_json="["
first=1
for g in sudo wheel admin adm root; do
  members=$(getent group "$g" 2>/dev/null | cut -d: -f4)
  getent group "$g" >/dev/null 2>&1 || continue
  if [ $first -eq 1 ]; then first=0; else groups_json+=","; fi
  groups_json+=$'\n'"$(evidence_object \
    "group" "$(evidence_string "$g")" \
    "members" "$(printf '%s' "$members" | tr ',' '\n' | evidence_lines_array)")"
done
groups_json+=$'\n]'

# Password ageing defaults
defs_value() { grep -E "^\s*$1\s" /etc/login.defs 2>/dev/null | awk '{ print $2 }' | head -n 1; }
login_defs=$(evidence_object \
  "pass_max_days" "$(evidence_number "$(defs_value PASS_MAX_DAYS)")" \
  "pass_min_days" "$(evidence_number "$(defs_value PASS_MIN_DAYS)")" \
  "pass_warn_age" "$(evidence_number "$(defs_value PASS_WARN_AGE)")" \
  "encrypt_method" "$(evidence_string "$(defs_value ENCRYPT_METHOD)")" \
  "umask" "$(evidence_string "$(defs_value UMASK)")")

# sudoers (root): active lines only, plus counts
sudo_lines() {
  local f
  for f in /etc/sudoers /etc/sudoers.d/*; do
    [ -f "$f" ] && [ -r "$f" ] || continue
    grep -EvH '^\s*(#|$)' "$f" 2>/dev/null
  done
}
if [ "$is_root" = "true" ]; then
  sudo_json=$(sudo_lines | evidence_lines_array)
  nopasswd=$(sudo_lines | grep -c 'NOPASSWD' || true)
  all_all=$(sudo_lines | grep -Ec '\bALL\s*=\s*\(ALL(:ALL)?\)\s*(NOPASSWD:\s*)?ALL' || true)
  sudo_readable="true"
else
  sudo_json="[]"; nopasswd="null"; all_all="null"; sudo_readable="false"
fi
sudoers=$(evidence_object \
  "readable" "$sudo_readable" \
  "sudo_version" "$(evidence_string "$(sudo -V 2>/dev/null | head -n 1)")" \
  "nopasswd_entries" "$(evidence_number "$nopasswd")" \
  "unrestricted_all_entries" "$(evidence_number "$all_all")" \
  "active_lines" "$sudo_json")

data=$(evidence_object \
  "is_root" "$is_root" \
  "login_accounts" "$accounts" \
  "uid_zero_accounts" "$uid0" \
  "privileged_groups" "$groups_json" \
  "login_defs" "$login_defs" \
  "sudoers" "$sudoers")

file=$(evidence_write "ISO27001:A.5.15,ISO27001:A.5.16,ISO27001:A.5.18,ISO27001:A.8.2,CIS8:5.1,CIS8:5.2,CIS8:5.4" \
  "linux/users-sudoers-evidence.sh" "$data" "$OUT_DIR") || exit 1
echo "Evidence written: $file"
evidence_verify "$file" >/dev/null && echo "SHA-256 verified."
