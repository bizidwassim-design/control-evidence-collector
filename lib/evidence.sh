#!/usr/bin/env bash
# shellcheck shell=bash
#
# Shared helper for the Linux evidence collectors: JSON building blocks, the common envelope and the
# SHA-256 scheme shared with lib/Evidence.psm1 and lib/evidence.py.
#
#   Envelope : { control_ids, collector, host, collected_at_utc, collected_by, data, sha256 }
#   Hash     : SHA-256 of the file bytes with the sha256 value set to 64 zeros, then substituted.
#
# Usage (from a collector):
#   source "$(dirname "$0")/../../lib/evidence.sh"
#   data=$(evidence_object "key" "$(evidence_string "value")" ...)
#   evidence_write "ISO27001:A.8.8,CIS8:7.3" "linux/patch-status-evidence.sh" "$data" "$OUT_DIR"
#
# Requirements: bash 4+, coreutils (sha256sum or shasum), sed, awk, tr. No jq needed.
# Author: Wassim Bizid - MIT License - https://github.com/bizidwassim-design/control-evidence-collector

EVIDENCE_PLACEHOLDER="0000000000000000000000000000000000000000000000000000000000000000"

# ---------------------------------------------------------------- JSON primitives

# Escape stdin as the body of a JSON string (no surrounding quotes).
evidence_escape() {
  tr -d '\000-\010\013\014\016-\037' \
    | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' -e 's/\r/\\r/g' \
    | awk 'BEGIN { ORS = "" } NR > 1 { print "\\n" } { print }'
}

# evidence_string VALUE  ->  "VALUE" (escaped)
evidence_string() {
  printf '"%s"' "$(printf '%s' "$1" | evidence_escape)"
}

# evidence_number VALUE  ->  VALUE if numeric, otherwise null
evidence_number() {
  if printf '%s' "$1" | grep -Eq '^-?[0-9]+(\.[0-9]+)?$'; then
    printf '%s' "$1"
  else
    printf 'null'
  fi
}

# evidence_bool VALUE  ->  true / false  (anything but "true", "yes", "1" is false)
evidence_bool() {
  case "${1,,}" in
    true|yes|1) printf 'true' ;;
    *) printf 'false' ;;
  esac
}

# Reads lines from stdin and prints a JSON array of strings (empty lines dropped).
evidence_lines_array() {
  local first=1 line
  printf '['
  while IFS= read -r line || [ -n "$line" ]; do
    [ -z "$line" ] && continue
    if [ $first -eq 1 ]; then first=0; else printf ','; fi
    printf '\n    %s' "$(evidence_string "$line")"
  done
  printf '\n  ]'
}

# evidence_object KEY RAW_JSON [KEY RAW_JSON ...]  ->  { "KEY": RAW_JSON, ... }
evidence_object() {
  local first=1
  printf '{'
  while [ $# -ge 2 ]; do
    if [ $first -eq 1 ]; then first=0; else printf ','; fi
    printf '\n  %s: %s' "$(evidence_string "$1")" "$2"
    shift 2
  done
  printf '\n}'
}

# evidence_command CMD [ARGS...]  ->  { "command": "...", "exit_code": N, "stdout": "...", "stderr": "..." }
# Runs the command with a 60 s timeout when `timeout` exists; never aborts the collector.
evidence_command() {
  local out err rc errfile
  errfile=$(mktemp)
  if command -v timeout >/dev/null 2>&1; then
    out=$(timeout 60 "$@" 2>"$errfile"); rc=$?
  else
    out=$("$@" 2>"$errfile"); rc=$?
  fi
  err=$(cat "$errfile"); rm -f "$errfile"
  evidence_object \
    "command" "$(evidence_string "$*")" \
    "exit_code" "$(evidence_number "$rc")" \
    "stdout" "$(evidence_string "$out")" \
    "stderr" "$(evidence_string "$err")"
}

# evidence_file_stat PATH -> { "path", "exists", "mode", "owner", "group", "size", "modified_utc" }
evidence_file_stat() {
  local p="$1"
  if [ -e "$p" ]; then
    local mode owner group size mtime
    mode=$(stat -c '%a' "$p" 2>/dev/null || stat -f '%Lp' "$p" 2>/dev/null)
    owner=$(stat -c '%U' "$p" 2>/dev/null || stat -f '%Su' "$p" 2>/dev/null)
    group=$(stat -c '%G' "$p" 2>/dev/null || stat -f '%Sg' "$p" 2>/dev/null)
    size=$(stat -c '%s' "$p" 2>/dev/null || stat -f '%z' "$p" 2>/dev/null)
    mtime=$(date -u -r "$p" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)
    evidence_object \
      "path" "$(evidence_string "$p")" \
      "exists" "true" \
      "mode" "$(evidence_string "$mode")" \
      "owner" "$(evidence_string "$owner")" \
      "group" "$(evidence_string "$group")" \
      "size" "$(evidence_number "$size")" \
      "modified_utc" "$(evidence_string "$mtime")"
  else
    evidence_object "path" "$(evidence_string "$p")" "exists" "false"
  fi
}

# ---------------------------------------------------------------- hashing and envelope

evidence_sha256_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | cut -d' ' -f1
  else
    echo "evidence.sh: neither sha256sum nor shasum is available" >&2
    return 1
  fi
}

# evidence_write CONTROL_IDS_CSV COLLECTOR DATA_JSON [OUT_DIR] [HOST] [COLLECTED_BY] [COLLECTED_AT_UTC]
# Writes <collector-basename>_<host>_<timestamp>.json and prints its path.
evidence_write() {
  local ids="$1" collector="$2" data="$3" out_dir="${4:-./evidence}"
  local host="${5:-$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown)}"
  local by="${6:-$(id -un 2>/dev/null || echo unknown)}"
  local at="${7:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"

  local ids_json
  ids_json=$(printf '%s' "$ids" | tr ',' '\n' | sed 's/^ *//; s/ *$//' | evidence_lines_array)

  local envelope
  envelope=$(printf '{\n  "control_ids": %s,\n  "collector": %s,\n  "host": %s,\n  "collected_at_utc": %s,\n  "collected_by": %s,\n  "data": %s,\n  "sha256": "%s"\n}' \
    "$ids_json" "$(evidence_string "$collector")" "$(evidence_string "$host")" \
    "$(evidence_string "$at")" "$(evidence_string "$by")" "$data" "$EVIDENCE_PLACEHOLDER")

  local hash
  hash=$(printf '%s\n' "$envelope" | evidence_sha256_stdin) || return 1

  local base safe_host stamp file
  base=$(basename "$collector" .sh)
  safe_host=$(printf '%s' "$host" | tr -c 'A-Za-z0-9._-' '-')
  stamp=$(printf '%s' "$at" | tr -d ':-')
  mkdir -p "$out_dir"
  file="$out_dir/${base}_${safe_host}_${stamp}.json"
  printf '%s\n' "${envelope//$EVIDENCE_PLACEHOLDER/$hash}" > "$file"
  printf '%s\n' "$file"
}

# evidence_verify FILE -> prints "OK <hash>" or "MISMATCH <expected> <actual>"; exit 1 on mismatch.
evidence_verify() {
  local file="$1" expected actual
  expected=$(grep -Eo '"sha256": *"[0-9a-f]{64}"' "$file" | tail -n 1 | grep -Eo '[0-9a-f]{64}')
  if [ -z "$expected" ]; then
    echo "INVALID $file (no sha256 field)"
    return 1
  fi
  actual=$(sed "s/$expected/$EVIDENCE_PLACEHOLDER/g" "$file" | evidence_sha256_stdin)
  if [ "$actual" = "$expected" ]; then
    echo "OK $expected $file"
  else
    echo "MISMATCH expected=$expected actual=$actual $file"
    return 1
  fi
}

# ---------------------------------------------------------------- common collector helpers

# Prints "true" when running as root.
evidence_is_root() {
  if [ "$(id -u)" -eq 0 ]; then printf 'true'; else printf 'false'; fi
}

# Non-comment, non-empty lines of a file as a JSON array (or [] when unreadable).
evidence_config_lines() {
  if [ -r "$1" ]; then
    grep -Ev '^\s*(#|$)' "$1" | evidence_lines_array
  else
    printf '[]'
  fi
}
