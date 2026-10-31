#!/usr/bin/env bash
# patch-status-evidence.sh - Patch status evidence for a Linux host (apt, dnf/yum or zypper).
#
# Read-only. Records the distribution and kernel, the package manager, pending updates (count and list),
# the last successful update run, whether a reboot is required, the automatic-update configuration and
# writes a hashed JSON envelope. Never installs or refreshes anything.
#
# Controls : ISO27001:A.8.8 | CIS8:7.3, CIS8:7.4
# Requires : bash 4+, coreutils. Normal user is enough on most distributions; dnf/zypper may need root
#            to read their caches (the error is recorded, not fatal).
# Usage    : ./patch-status-evidence.sh [output-dir]
# Author   : Wassim Bizid - MIT License - https://github.com/bizidwassim-design/control-evidence-collector
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../lib/evidence.sh
source "$SCRIPT_DIR/../../lib/evidence.sh"

OUT_DIR="${1:-./evidence}"

# Distribution and kernel
os_release=$(evidence_config_lines /etc/os-release)
pretty_name=$(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"')
kernel_running=$(uname -r 2>/dev/null)
kernel_installed=$(find /boot -maxdepth 1 -name 'vmlinuz-*' 2>/dev/null | sed 's#.*/vmlinuz-##' | sort -V | tail -n 1)
uptime_days=$(awk '{ printf "%.1f", $1 / 86400 }' /proc/uptime 2>/dev/null)

# Package manager detection
if command -v apt-get >/dev/null 2>&1; then pm="apt"
elif command -v dnf >/dev/null 2>&1; then pm="dnf"
elif command -v yum >/dev/null 2>&1; then pm="yum"
elif command -v zypper >/dev/null 2>&1; then pm="zypper"
else pm="unknown"; fi

pending_list="[]"; pending_count="null"; last_update="null"; auto_update="{}"; reboot_required="null"
case "$pm" in
  apt)
    # "apt list" warns about CLI stability on stderr; stdout is what we want
    upgradable=$(apt list --upgradable 2>/dev/null | grep -E '/' | sed 's/\s\+/ /g')
    pending_list=$(printf '%s\n' "$upgradable" | evidence_lines_array)
    pending_count=$(printf '%s\n' "$upgradable" | grep -c '/' || true)
    security_count=$(printf '%s\n' "$upgradable" | grep -ci 'security' || true)
    stamp="/var/lib/apt/periodic/update-success-stamp"
    [ -e "$stamp" ] && last_update="$(evidence_string "$(date -u -r "$stamp" '+%Y-%m-%dT%H:%M:%SZ')")"
    last_install=$(grep -E '^(Start-Date|End-Date)' /var/log/apt/history.log 2>/dev/null | tail -n 1 | sed 's/^End-Date: //; s/^Start-Date: //')
    if [ -e /var/run/reboot-required ]; then reboot_required="true"; else reboot_required="false"; fi
    auto_update=$(evidence_object \
      "unattended_upgrades_installed" "$(if command -v unattended-upgrade >/dev/null 2>&1; then echo true; else echo false; fi)" \
      "apt_periodic_config" "$(evidence_config_lines /etc/apt/apt.conf.d/20auto-upgrades)" \
      "last_history_entry" "$(evidence_string "$last_install")")
    ;;
  dnf|yum)
    # exit code 100 = updates available, 0 = none, other = error
    raw=$($pm -q check-update 2>&1); rc=$?
    if [ $rc -eq 100 ] || [ $rc -eq 0 ]; then
      upgradable=$(printf '%s\n' "$raw" | grep -E '^[[:alnum:]._+-]+\.[[:alnum:]_]+[[:space:]]' | sed 's/\s\+/ /g')
      pending_list=$(printf '%s\n' "$upgradable" | evidence_lines_array)
      pending_count=$(printf '%s\n' "$upgradable" | grep -c . || true)
    else
      pending_list=$(evidence_object "error" "$(evidence_string "$raw")")
    fi
    security_count=$($pm -q updateinfo list security 2>/dev/null | grep -c . || true)
    last_update="$(evidence_string "$($pm -q history list 2>/dev/null | sed -n '2p' | sed 's/\s\+/ /g')")"
    if command -v needs-restarting >/dev/null 2>&1; then
      if needs-restarting -r >/dev/null 2>&1; then reboot_required="false"; else reboot_required="true"; fi
    fi
    auto_update=$(evidence_object \
      "dnf_automatic_timer" "$(evidence_string "$(systemctl is-enabled dnf-automatic.timer 2>/dev/null || systemctl is-enabled dnf-automatic-install.timer 2>/dev/null || echo not-found)")" \
      "automatic_conf" "$(evidence_config_lines /etc/dnf/automatic.conf)")
    ;;
  zypper)
    upgradable=$(zypper -q --non-interactive lu 2>/dev/null | grep -E '^\s*v?\s*\|' | sed 's/\s\+/ /g')
    pending_list=$(printf '%s\n' "$upgradable" | evidence_lines_array)
    pending_count=$(printf '%s\n' "$upgradable" | grep -c . || true)
    security_count=$(zypper -q --non-interactive lp --category security 2>/dev/null | grep -c '|' || true)
    if zypper -q needs-rebooting >/dev/null 2>&1; then reboot_required="false"; else reboot_required="true"; fi
    ;;
  *)
    security_count="null"
    ;;
esac

data=$(evidence_object \
  "is_root" "$(evidence_is_root)" \
  "distribution" "$(evidence_string "$pretty_name")" \
  "os_release" "$os_release" \
  "kernel" "$(evidence_object \
      "running" "$(evidence_string "$kernel_running")" \
      "newest_installed" "$(evidence_string "$kernel_installed")" \
      "running_is_newest" "$(if [ -n "$kernel_installed" ] && [ "$kernel_running" = "$kernel_installed" ]; then echo true; elif [ -z "$kernel_installed" ]; then echo null; else echo false; fi)")" \
  "uptime_days" "$(evidence_number "$uptime_days")" \
  "package_manager" "$(evidence_string "$pm")" \
  "pending_updates" "$(evidence_object \
      "count" "$(evidence_number "$pending_count")" \
      "security_count" "$(evidence_number "$security_count")" \
      "packages" "$pending_list")" \
  "last_update_run" "$last_update" \
  "reboot_required" "$reboot_required" \
  "automatic_updates" "$auto_update")

file=$(evidence_write "ISO27001:A.8.8,CIS8:7.3,CIS8:7.4" "linux/patch-status-evidence.sh" "$data" "$OUT_DIR") || exit 1
echo "Evidence written: $file"
evidence_verify "$file" >/dev/null && echo "SHA-256 verified."
