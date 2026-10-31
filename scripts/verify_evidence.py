#!/usr/bin/env python3
"""Recompute the SHA-256 of every evidence file in one or more folders and print a manifest.

Usage:
    python scripts/verify_evidence.py evidence/                # table on stdout, exit 1 on any failure
    python scripts/verify_evidence.py evidence/ --manifest manifest.json
    python scripts/verify_evidence.py a.json b.json --json     # machine-readable output

The manifest lists every file with its collector, host, timestamp, control ids, hash and status, and
carries its own SHA-256 so an auditor can pin the whole evidence set with one value.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from evidence import VerifyResult, sha256_hex, utc_now_iso, verify_file  # noqa: E402


def collect_paths(inputs: list[str]) -> list[Path]:
    paths: list[Path] = []
    for item in inputs:
        p = Path(item)
        if p.is_dir():
            paths.extend(sorted(x for x in p.rglob("*.json") if x.is_file()))
        elif p.is_file():
            paths.append(p)
        else:
            print(f"warning: {item} does not exist", file=sys.stderr)
    return paths


def entry(result: VerifyResult, root: Path) -> dict:
    doc = result.envelope or {}
    try:
        rel = result.path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        rel = result.path.as_posix()
    return {
        "file": rel,
        "status": result.status,
        "sha256": result.expected,
        "recomputed_sha256": result.actual,
        "collector": doc.get("collector"),
        "host": doc.get("host"),
        "collected_at_utc": doc.get("collected_at_utc"),
        "collected_by": doc.get("collected_by"),
        "control_ids": doc.get("control_ids"),
        "message": result.message,
    }


def print_table(entries: list[dict]) -> None:
    widths = {
        "status": max(6, *(len(e["status"]) for e in entries)),
        "collector": max(9, *(len(str(e["collector"] or "")) for e in entries)),
        "host": max(4, *(len(str(e["host"] or "")) for e in entries)),
        "ts": 20,
    }
    header = f"{'STATUS':<{widths['status']}}  {'COLLECTOR':<{widths['collector']}}  {'HOST':<{widths['host']}}  {'COLLECTED_AT_UTC':<{widths['ts']}}  SHA256 (first 16)  FILE"
    print(header)
    print("-" * len(header))
    for e in entries:
        digest = (e["sha256"] or "")[:16]
        print(
            f"{e['status']:<{widths['status']}}  {str(e['collector'] or ''):<{widths['collector']}}  "
            f"{str(e['host'] or ''):<{widths['host']}}  {str(e['collected_at_utc'] or ''):<{widths['ts']}}  "
            f"{digest:<17}  {e['file']}" + (f"  ({e['message']})" if e["message"] else "")
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify hashed evidence files and print a manifest.")
    parser.add_argument("paths", nargs="+", help="evidence files or folders (searched recursively for *.json)")
    parser.add_argument("--manifest", metavar="FILE", help="write the manifest as JSON to this file")
    parser.add_argument("--json", action="store_true", help="print the manifest as JSON instead of a table")
    parser.add_argument("--root", default=".", help="folder that file names are shown relative to (default: current)")
    args = parser.parse_args(argv)

    paths = collect_paths(args.paths)
    if not paths:
        print("no evidence files found", file=sys.stderr)
        return 2

    root = Path(args.root)
    entries = [entry(verify_file(p), root) for p in paths]
    ok = sum(1 for e in entries if e["status"] == "OK")
    failed = len(entries) - ok

    manifest = {
        "generated_at_utc": utc_now_iso(),
        "files_total": len(entries),
        "files_ok": ok,
        "files_failed": failed,
        "files": entries,
    }
    manifest_bytes = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    manifest["manifest_sha256"] = sha256_hex(manifest_bytes)

    if args.json:
        print(json.dumps(manifest, indent=2, ensure_ascii=False))
    else:
        print_table(entries)
        print()
        print(f"{ok} OK, {failed} failed, {len(entries)} total. Manifest SHA-256: {manifest['manifest_sha256']}")

    if args.manifest:
        out = Path(args.manifest)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8", newline="\n") as fh:
            json.dump(manifest, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        if not args.json:
            print(f"manifest written: {out}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
