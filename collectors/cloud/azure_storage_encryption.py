#!/usr/bin/env python3
"""Collect storage-account encryption and exposure evidence for Azure subscriptions (read-only).

For every storage account in the selected subscription(s) records: SKU and kind, encryption key source
(Microsoft-managed or customer-managed in Key Vault), infrastructure (double) encryption, per-service
encryption, HTTPS-only, minimum TLS version, public blob access, shared-key access, public network
access and the default network action. Summarises the accounts that fall short of the usual baseline.

Requires: azure-identity, azure-mgmt-storage, azure-mgmt-resource
          (pip install azure-identity azure-mgmt-storage azure-mgmt-resource)
Sign-in: interactive browser by default (--auth browser) or the DefaultAzureCredential chain
         (--auth default, for Azure CLI / managed identity). The Reader role on the subscription is enough.

Controls: ISO27001:A.5.23, ISO27001:A.8.20, ISO27001:A.8.24 | CIS8:3.3, CIS8:3.10, CIS8:3.11
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
    from azure.core.exceptions import AzureError
    from azure.identity import DefaultAzureCredential, InteractiveBrowserCredential
    from azure.mgmt.resource import SubscriptionClient
    from azure.mgmt.storage import StorageManagementClient
except ImportError:  # pragma: no cover
    print("Azure SDK packages are required: pip install azure-identity azure-mgmt-storage azure-mgmt-resource", file=sys.stderr)
    sys.exit(2)

CONTROL_IDS = ["ISO27001:A.5.23", "ISO27001:A.8.20", "ISO27001:A.8.24", "CIS8:3.3", "CIS8:3.10", "CIS8:3.11"]
COLLECTOR = "cloud/azure_storage_encryption.py"


def enum_value(value: Any) -> Any:
    """Azure SDK enums serialise badly; keep their string value."""
    return getattr(value, "value", value)


def account_evidence(acct: Any) -> dict[str, Any]:
    enc = acct.encryption
    services = getattr(enc, "services", None)
    net = acct.network_rule_set

    def svc(name: str) -> dict[str, Any] | None:
        s = getattr(services, name, None) if services else None
        if s is None:
            return None
        return {"enabled": bool(s.enabled), "key_type": enum_value(s.key_type)}

    return {
        "name": acct.name,
        "resource_group": acct.id.split("/resourceGroups/")[1].split("/")[0] if acct.id and "/resourceGroups/" in acct.id else None,
        "location": acct.location,
        "sku": enum_value(acct.sku.name) if acct.sku else None,
        "kind": enum_value(acct.kind),
        "created_utc": acct.creation_time.strftime("%Y-%m-%dT%H:%M:%SZ") if acct.creation_time else None,
        "encryption": {
            "key_source": enum_value(getattr(enc, "key_source", None)),
            "customer_managed_key": enum_value(getattr(enc, "key_source", None)) == "Microsoft.Keyvault",
            "require_infrastructure_encryption": bool(getattr(enc, "require_infrastructure_encryption", False)),
            "blob": svc("blob"),
            "file": svc("file"),
            "table": svc("table"),
            "queue": svc("queue"),
        },
        "https_traffic_only": bool(acct.enable_https_traffic_only),
        "minimum_tls_version": enum_value(acct.minimum_tls_version),
        "allow_blob_public_access": acct.allow_blob_public_access,
        "allow_shared_key_access": acct.allow_shared_key_access,
        "public_network_access": enum_value(getattr(acct, "public_network_access", None)),
        "network_default_action": enum_value(net.default_action) if net else None,
        "network_ip_rules": len(net.ip_rules or []) if net else None,
        "network_vnet_rules": len(net.virtual_network_rules or []) if net else None,
        "private_endpoints": len(acct.private_endpoint_connections or []),
        "allow_cross_tenant_replication": getattr(acct, "allow_cross_tenant_replication", None),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Azure storage-account encryption and exposure evidence (read-only).")
    parser.add_argument("--subscription", action="append", help="subscription id (repeatable). Default: every subscription visible to the identity")
    parser.add_argument("--auth", choices=["browser", "default"], default="browser", help="interactive browser (default) or DefaultAzureCredential")
    parser.add_argument("--tenant", help="tenant id for the interactive sign-in")
    parser.add_argument("--output-dir", default="evidence")
    args = parser.parse_args(argv)

    if args.auth == "browser":
        credential = InteractiveBrowserCredential(tenant_id=args.tenant) if args.tenant else InteractiveBrowserCredential()
    else:
        credential = DefaultAzureCredential()

    try:
        sub_client = SubscriptionClient(credential)
        subscriptions = {s.subscription_id: s.display_name for s in sub_client.subscriptions.list()}
    except AzureError as exc:
        print(f"cannot list subscriptions: {exc}", file=sys.stderr)
        return 1
    targets = args.subscription or sorted(subscriptions)
    if not targets:
        print("no subscription visible to this identity", file=sys.stderr)
        return 1

    per_sub: list[dict[str, Any]] = []
    all_accounts: list[dict[str, Any]] = []
    for sub_id in targets:
        entry: dict[str, Any] = {"subscription_id": sub_id, "display_name": subscriptions.get(sub_id)}
        try:
            client = StorageManagementClient(credential, sub_id)
            accounts = [account_evidence(a) for a in client.storage_accounts.list()]
            entry["storage_accounts"] = accounts
            all_accounts.extend(accounts)
        except AzureError as exc:
            entry["error"] = str(exc)
        per_sub.append(entry)

    data: dict[str, Any] = {
        "subscriptions_total": len(per_sub),
        "subscriptions": per_sub,
        "summary": {
            "storage_accounts_total": len(all_accounts),
            "customer_managed_key": sum(1 for a in all_accounts if a["encryption"]["customer_managed_key"]),
            "infrastructure_encryption": sum(1 for a in all_accounts if a["encryption"]["require_infrastructure_encryption"]),
            "accounts_allowing_http": [a["name"] for a in all_accounts if not a["https_traffic_only"]],
            "accounts_tls_below_1_2": [a["name"] for a in all_accounts if a["minimum_tls_version"] not in ("TLS1_2", "TLS1_3")],
            "accounts_allowing_public_blob_access": [a["name"] for a in all_accounts if a["allow_blob_public_access"] is not False],
            "accounts_allowing_shared_key": [a["name"] for a in all_accounts if a["allow_shared_key_access"] is not False],
            "accounts_network_default_allow": [a["name"] for a in all_accounts if a["network_default_action"] == "Allow"],
        },
    }

    host = f"azure-subscription:{targets[0]}" if len(targets) == 1 else f"azure-subscriptions:{len(targets)}"
    envelope = build_envelope(CONTROL_IDS, COLLECTOR, data, host=host)
    path = write_evidence(envelope, args.output_dir)
    print(f"Evidence written: {path}")
    print(f"SHA-256        : {envelope['sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
