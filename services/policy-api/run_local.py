from __future__ import annotations

import argparse
import json

from pounce_sentinel.api import (
    create_exception,
    explain_verdict,
    scan_manifest,
    scan_sbom,
    service_status,
    sync_feeds,
    vet_dependency,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run local Pounce Sentinel API scenarios.")
    subcommands = parser.add_subparsers(dest="command", required=True)

    subcommands.add_parser("status")
    subcommands.add_parser("sync-feeds")

    vet = subcommands.add_parser("vet")
    vet.add_argument("ecosystem", choices=["npm", "pypi"])
    vet.add_argument("package_name")
    vet.add_argument("version")
    vet.add_argument("--repository", default="org/agent-service")
    vet.add_argument("--source", default="local-cli")
    vet.add_argument("--actor", default="developer")

    scan = subcommands.add_parser("scan")
    scan.add_argument("ecosystem", choices=["npm", "pypi"])
    scan.add_argument("manifest_path")

    scan_sbom_cmd = subcommands.add_parser("scan-sbom")
    scan_sbom_cmd.add_argument("sbom_path")

    explain = subcommands.add_parser("explain")
    explain.add_argument("audit_id")

    exception = subcommands.add_parser("exception")
    exception.add_argument("audit_id")
    exception.add_argument("reason")
    exception.add_argument("--approver", default="local-reviewer")

    args = parser.parse_args()

    if args.command == "status":
        print(json.dumps(service_status(), indent=2))
        return

    if args.command == "sync-feeds":
        print(json.dumps(sync_feeds({"source": "local-cli"}), indent=2))
        return

    if args.command == "explain":
        print(json.dumps(explain_verdict(args.audit_id), indent=2))
        return

    if args.command == "exception":
        print(
            json.dumps(
                create_exception(
                    {
                        "auditId": args.audit_id,
                        "reason": args.reason,
                        "approver": args.approver,
                    }
                ),
                indent=2,
            )
        )
        return

    if args.command == "vet":
        result = vet_dependency(
            {
                "ecosystem": args.ecosystem,
                "packageName": args.package_name,
                "version": args.version,
                "repository": args.repository,
                "source": args.source,
                "actor": args.actor,
            }
        )
        print(json.dumps(result, indent=2))
        return

    if args.command == "scan-sbom":
        with open(args.sbom_path, "r", encoding="utf-8") as sbom_file:
            result = scan_sbom(
                {
                    "content": sbom_file.read(),
                    "sbomPath": args.sbom_path,
                    "repository": "org/agent-service",
                    "source": "local-cli",
                    "actor": "developer",
                }
            )
        print(json.dumps(result, indent=2))
        return

    with open(args.manifest_path, "r", encoding="utf-8") as manifest:
        result = scan_manifest(
            {
                "ecosystem": args.ecosystem,
                "manifestPath": args.manifest_path,
                "content": manifest.read(),
                "repository": "org/agent-service",
                "source": "local-cli",
                "actor": "developer",
            }
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
