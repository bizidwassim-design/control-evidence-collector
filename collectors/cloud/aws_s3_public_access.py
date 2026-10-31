#!/usr/bin/env python3
"""Collect S3 public-access and encryption evidence for one AWS account (read-only).

Records the account-level Block Public Access configuration and, for every bucket, its region, the
bucket-level Block Public Access settings, the policy status (IsPublic), ACL grants to AllUsers or
AuthenticatedUsers, default encryption, versioning and server access logging. Summarises the buckets
that are public by policy or ACL, lack default encryption or lack a full public-access block.

Requires: boto3 (pip install boto3) and credentials from the usual AWS sources (profile, SSO, env).
Permissions (read-only): s3:ListAllMyBuckets, s3:GetBucketLocation, s3:GetBucketPublicAccessBlock,
s3:GetBucketPolicyStatus, s3:GetBucketAcl, s3:GetEncryptionConfiguration, s3:GetBucketVersioning,
s3:GetBucketLogging, s3:GetAccountPublicAccessBlock, sts:GetCallerIdentity. The SecurityAudit managed
policy covers all of them.

Controls: ISO27001:A.5.23, ISO27001:A.8.3, ISO27001:A.8.24 | CIS8:3.3, CIS8:3.11, CIS8:8.5
Author: Wassim Bizid - MIT License - https://github.com/bizidwassim-design/control-evidence-collector
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "lib"))
from evidence import build_envelope, write_evidence  # noqa: E402

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:  # pragma: no cover
    print("boto3 is required: pip install boto3", file=sys.stderr)
    sys.exit(2)

CONTROL_IDS = ["ISO27001:A.5.23", "ISO27001:A.8.3", "ISO27001:A.8.24", "CIS8:3.3", "CIS8:3.11", "CIS8:8.5"]
COLLECTOR = "cloud/aws_s3_public_access.py"
PUBLIC_GRANTEES = {
    "http://acs.amazonaws.com/groups/global/AllUsers": "AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "AuthenticatedUsers",
}


def error_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "Unknown")


def public_access_block(fn, **kwargs) -> dict[str, Any] | None:
    """Return the four PAB flags, None when no configuration exists, or {'error': ...}."""
    try:
        cfg = fn(**kwargs)["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if error_code(exc) == "NoSuchPublicAccessBlockConfiguration":
            return None
        return {"error": error_code(exc)}
    return {
        "block_public_acls": cfg.get("BlockPublicAcls", False),
        "ignore_public_acls": cfg.get("IgnorePublicAcls", False),
        "block_public_policy": cfg.get("BlockPublicPolicy", False),
        "restrict_public_buckets": cfg.get("RestrictPublicBuckets", False),
    }


def is_full_block(pab: dict[str, Any] | None) -> bool:
    return bool(pab) and "error" not in pab and all(pab.values())


def bucket_evidence(s3, name: str) -> dict[str, Any]:
    row: dict[str, Any] = {"name": name}

    try:
        loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
        row["region"] = loc or "us-east-1"
    except ClientError as exc:
        row["region"] = None
        row["region_error"] = error_code(exc)

    row["public_access_block"] = public_access_block(s3.get_public_access_block, Bucket=name)

    try:
        row["policy_is_public"] = bool(s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]["IsPublic"])
    except ClientError as exc:
        row["policy_is_public"] = False if error_code(exc) == "NoSuchBucketPolicy" else None
        if error_code(exc) != "NoSuchBucketPolicy":
            row["policy_error"] = error_code(exc)

    try:
        grants = s3.get_bucket_acl(Bucket=name).get("Grants", [])
        public_grants = [
            {"grantee": PUBLIC_GRANTEES[g["Grantee"]["URI"]], "permission": g.get("Permission")}
            for g in grants
            if g.get("Grantee", {}).get("Type") == "Group" and g["Grantee"].get("URI") in PUBLIC_GRANTEES
        ]
        row["acl_public_grants"] = public_grants
        row["acl_is_public"] = bool(public_grants)
    except ClientError as exc:
        row["acl_public_grants"] = None
        row["acl_is_public"] = None
        row["acl_error"] = error_code(exc)

    try:
        rules = s3.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]["Rules"]
        first = rules[0]["ApplyServerSideEncryptionByDefault"] if rules else {}
        row["default_encryption"] = {
            "algorithm": first.get("SSEAlgorithm"),
            "kms_key_configured": bool(first.get("KMSMasterKeyID")),
            "bucket_key_enabled": bool(rules[0].get("BucketKeyEnabled")) if rules else None,
        }
    except ClientError as exc:
        row["default_encryption"] = None if error_code(exc) == "ServerSideEncryptionConfigurationNotFoundError" else {"error": error_code(exc)}

    try:
        row["versioning"] = s3.get_bucket_versioning(Bucket=name).get("Status", "Disabled")
    except ClientError as exc:
        row["versioning"] = {"error": error_code(exc)}

    try:
        logging_cfg = s3.get_bucket_logging(Bucket=name).get("LoggingEnabled")
        row["access_logging"] = {"enabled": True, "target_bucket": logging_cfg["TargetBucket"]} if logging_cfg else {"enabled": False}
    except ClientError as exc:
        row["access_logging"] = {"error": error_code(exc)}

    return row


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="S3 public-access and encryption evidence (read-only).")
    parser.add_argument("--profile", help="AWS named profile")
    parser.add_argument("--region", default="us-east-1", help="region for the STS/S3 control endpoints")
    parser.add_argument("--output-dir", default="evidence")
    parser.add_argument("--max-buckets", type=int, default=500, help="safety limit for very large accounts")
    args = parser.parse_args(argv)

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    try:
        identity = session.client("sts").get_caller_identity()
    except (BotoCoreError, ClientError) as exc:
        print(f"cannot determine the caller identity: {exc}", file=sys.stderr)
        return 1
    account_id = identity["Account"]

    s3 = session.client("s3")
    data: dict[str, Any] = {"account_id": account_id, "caller_arn": identity.get("Arn")}

    data["account_public_access_block"] = public_access_block(session.client("s3control").get_public_access_block, AccountId=account_id)

    try:
        names = sorted(b["Name"] for b in s3.list_buckets().get("Buckets", []))
    except ClientError as exc:
        data["buckets"] = {"error": error_code(exc)}
        names = []
    data["buckets_total"] = len(names)
    data["buckets_truncated"] = len(names) > args.max_buckets
    buckets = [bucket_evidence(s3, n) for n in names[: args.max_buckets]]
    data["buckets"] = buckets

    data["summary"] = {
        "account_block_is_full": is_full_block(data["account_public_access_block"]),
        "buckets_public_by_policy": [b["name"] for b in buckets if b.get("policy_is_public")],
        "buckets_public_by_acl": [b["name"] for b in buckets if b.get("acl_is_public")],
        "buckets_without_full_block": [b["name"] for b in buckets if not is_full_block(b.get("public_access_block"))],
        "buckets_without_default_encryption": [b["name"] for b in buckets if not b.get("default_encryption") or "error" in b["default_encryption"]],
        "buckets_without_access_logging": [b["name"] for b in buckets if not (b.get("access_logging") or {}).get("enabled")],
        "buckets_with_versioning": sum(1 for b in buckets if b.get("versioning") == "Enabled"),
    }

    envelope = build_envelope(CONTROL_IDS, COLLECTOR, data, host=f"aws-account:{account_id}", collected_by=identity.get("Arn"))
    path = write_evidence(envelope, args.output_dir)
    print(f"Evidence written: {path}")
    print(f"SHA-256        : {envelope['sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
