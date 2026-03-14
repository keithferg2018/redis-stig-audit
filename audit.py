#!/usr/bin/env python3
"""redis-stig-audit — draft Redis container security audit tool."""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))

from runner import RedisRunner
from checks import ALL_CHECKERS
from output import report


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
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args()


def main():
    args = parse_args()
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

    target_info = {
        "Mode": args.mode,
        "Target": args.container or args.pod or f"{args.host}:{args.port}",
        "Timestamp": datetime.now(timezone.utc).isoformat(),
        "Connected": runner.test_connection(),
    }

    if not args.quiet:
        report.render(results, target_info)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(
                {
                    "target": target_info,
                    "snapshot": runner.snapshot(),
                    "results": [r.to_dict() for r in results],
                },
                f,
                indent=2,
            )
        print(f"[json] Written to {args.json}")


if __name__ == "__main__":
    main()
