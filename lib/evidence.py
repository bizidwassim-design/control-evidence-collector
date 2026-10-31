#!/usr/bin/env python3
"""Shared helper for the Python evidence collectors and the verifier.

Envelope: {control_ids, collector, host, collected_at_utc, collected_by, data, sha256}

Hash scheme (identical in lib/Evidence.psm1 and lib/evidence.sh):
  1. serialise the envelope with ``sha256`` set to 64 zeros;
  2. SHA-256 the exact UTF-8 bytes (LF, no BOM, trailing newline);
  3. write the same bytes with the placeholder replaced by the hex digest.

Verification replaces the digest with the placeholder and recomputes, so it works on raw bytes
whatever language produced the file and whatever its JSON formatting.

Author: Wassim Bizid - MIT License - https://github.com/bizidwassim-design/control-evidence-collector
"""
from __future__ import annotations

import getpass
import hashlib
import json
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PLACEHOLDER = "0" * 64
REQUIRED_FIELDS = ("control_ids", "collector", "host", "collected_at_utc", "collected_by", "data", "sha256")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def utc_now_iso() -> str:
    """Current UTC time as 2026-10-15T09:30:00Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_envelope(
    control_ids: list[str],
    collector: str,
    data: Any,
    host: str | None = None,
    collected_by: str | None = None,
    collected_at_utc: str | None = None,
) -> dict[str, Any]:
    """Return the envelope with the sha256 placeholder (key order is fixed on purpose)."""
    return {
        "control_ids": list(control_ids),
        "collector": collector,
        "host": host or socket.gethostname(),
        "collected_at_utc": collected_at_utc or utc_now_iso(),
        "collected_by": collected_by or _current_user(),
        "data": data,
        "sha256": PLACEHOLDER,
    }


def serialise(envelope: dict[str, Any]) -> bytes:
    """Deterministic UTF-8 bytes of the envelope (2-space indent, LF, trailing newline)."""
    text = json.dumps(envelope, indent=2, ensure_ascii=False) + "\n"
    return text.encode("utf-8")


def seal(envelope: dict[str, Any]) -> tuple[bytes, str]:
    """Return (final_bytes, hash). Leaves ``envelope['sha256']`` set to the hash."""
    for field in REQUIRED_FIELDS:
        if field not in envelope:
            raise ValueError(f"envelope is missing the '{field}' field")
    envelope["sha256"] = PLACEHOLDER
    raw = serialise(envelope)
    digest = sha256_hex(raw)
    envelope["sha256"] = digest
    return raw.replace(PLACEHOLDER.encode("ascii"), digest.encode("ascii")), digest


def default_file_name(envelope: dict[str, Any]) -> str:
    base = Path(str(envelope["collector"]).replace("\\", "/")).stem
    safe_host = re.sub(r"[^A-Za-z0-9._-]", "-", str(envelope["host"]))
    stamp = re.sub(r"[-:]", "", str(envelope["collected_at_utc"]))
    return f"{base}_{safe_host}_{stamp}.json"


def write_evidence(envelope: dict[str, Any], out_dir: str | Path = "evidence", file_name: str | None = None) -> Path:
    """Seal and write the envelope. Returns the path written."""
    final, _ = seal(envelope)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / (file_name or default_file_name(envelope))
    path.write_bytes(final)
    return path


@dataclass
class VerifyResult:
    path: Path
    status: str  # OK | MISMATCH | INVALID
    expected: str | None
    actual: str | None
    envelope: dict[str, Any] | None
    message: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "OK"


def verify_file(path: str | Path) -> VerifyResult:
    """Recompute the hash of one evidence file and compare it with the embedded value."""
    p = Path(path)
    raw = p.read_bytes()
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return VerifyResult(p, "INVALID", None, None, None, f"not valid UTF-8 JSON: {exc}")
    if not isinstance(doc, dict):
        return VerifyResult(p, "INVALID", None, None, None, "top-level value is not an object")
    missing = [f for f in REQUIRED_FIELDS if f not in doc]
    if missing:
        return VerifyResult(p, "INVALID", None, None, doc, f"missing fields: {', '.join(missing)}")
    expected = doc.get("sha256")
    if not isinstance(expected, str) or not _HEX64.match(expected):
        return VerifyResult(p, "INVALID", str(expected), None, doc, "sha256 is not a 64-character hex digest")
    actual = sha256_hex(raw.replace(expected.encode("ascii"), PLACEHOLDER.encode("ascii")))
    status = "OK" if actual == expected else "MISMATCH"
    return VerifyResult(p, status, expected, actual, doc, "" if status == "OK" else "content does not match its hash")


def _current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # pragma: no cover - exotic environments without a user database
        return "unknown"
