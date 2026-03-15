#!/usr/bin/env python3
"""redis-stig-audit — draft Redis container security audit tool."""
import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))

from runner import RedisRunner
from checks import ALL_CHECKERS
from output import report
from output.sarif import write_sarif
from output.bundle import write_bundle

TOOL_VERSION = "0.3.0-draft"
SCHEMA_VERSION = "2026-03-14"


def parse_args():
    p = argparse.ArgumentParser(description="Draft Redis CIS-style container audit")
    p.add_argument("--mode", choices=["docker", "kubectl", "direct"], default="docker")
    p.add_argument("--container")
    p.add_argument("--pod")
    p.add_argument("--namespace", default="default")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=6379)
    p.add_argument("--password", help="Redis password if required")
    p.add_argument("--json", metavar="FILE", help="Write raw results to FILE")
    p.add_argument("--sarif", metavar="FILE", help="Write SARIF 2.1.0 results to FILE")
    p.add_argument("--bundle", metavar="FILE", help="Write evidence bundle (zip) to FILE")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args()


def build_target_info(args, runner, timestamp: str) -> dict:
    return {
        "mode": args.mode,
        "namespace": args.namespace if args.mode == "kubectl" else None,
        "container": args.container,
        "pod": args.pod,
        "host": args.host if args.mode == "direct" else None,
        "port": args.port if args.mode == "direct" else None,
        "display_name": args.container or args.pod or f"{args.host}:{args.port}",
        "timestamp": timestamp,
        "connected": runner.test_connection(),
        "last_error": runner.last_error,
    }


def summarize(results) -> dict:
    status_counts = Counter(r.status.value for r in results)
    severity_counts = Counter(r.severity.value for r in results)
    actionable = sum(status_counts.get(k, 0) for k in ("FAIL", "WARN", "ERROR"))
    if status_counts.get("FAIL", 0) or status_counts.get("ERROR", 0):
        risk_posture = "HIGH RISK"
    elif status_counts.get("WARN", 0):
        risk_posture = "REVIEW REQUIRED"
    else:
        risk_posture = "BASELINE ACCEPTABLE"
    return {
        "status_counts": dict(status_counts),
        "severity_counts": dict(severity_counts),
        "actionable_findings": actionable,
        "risk_posture": risk_posture,
    }


def main():
    args = parse_args()
    timestamp = datetime.now(timezone.utc).isoformat()
    runner = RedisRunner(
        mode=args.mode,
        container=args.container,
        pod=args.pod,
        namespace=args.namespace,
        host=args.host,
        port=args.port,
        password=args.password,
        verbose=args.verbose,
    )

    results = []
    for checker_cls in ALL_CHECKERS:
        results.extend(checker_cls(runner).run())

    results = sorted(results, key=lambda r: (r.status.value, r.severity.value, r.check_id))
    target_info = build_target_info(args, runner, timestamp)
    summary = summarize(results)

    if not args.quiet:
        report.render(results, target_info, summary)

    if args.json or args.sarif or args.bundle:
        snapshot = runner.snapshot()
        document = {
            "schema_version": SCHEMA_VERSION,
            "tool": {
                "name": "redis-stig-audit",
                "version": TOOL_VERSION,
            },
            "target": target_info,
            "summary": summary,
            "snapshot": snapshot,
            "results": [r.to_dict() for r in results],
        }

        if args.json:
            with open(args.json, "w") as f:
                json.dump(document, f, indent=2)
            print(f"[json]   Written to {args.json}")

        if args.sarif:
            write_sarif(args.sarif, results, target_info, "redis-stig-audit", TOOL_VERSION)
            print(f"[sarif]  Written to {args.sarif}")

        if args.bundle:
            write_bundle(
                args.bundle,
                document,
                results,
                target_info,
                summary,
                snapshot,
                "redis-stig-audit",
                TOOL_VERSION,
            )
            print(f"[bundle] Written to {args.bundle}")


if __name__ == "__main__":
    main()
