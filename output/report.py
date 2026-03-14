from collections import Counter


def render(results, target_info):
    print("redis-stig-audit — draft report")
    print(f"Target: {target_info}")
    print()

    status_counts = Counter(r.status.value for r in results)
    sev_counts = Counter(r.severity.value for r in results)
    print("Summary:")
    print(
        f"  PASS {status_counts.get('PASS', 0)} | FAIL {status_counts.get('FAIL', 0)} | "
        f"WARN {status_counts.get('WARN', 0)} | ERROR {status_counts.get('ERROR', 0)} | SKIP {status_counts.get('SKIP', 0)}"
    )
    print(
        f"  CRITICAL {sev_counts.get('CRITICAL', 0)} | HIGH {sev_counts.get('HIGH', 0)} | "
        f"MEDIUM {sev_counts.get('MEDIUM', 0)} | LOW {sev_counts.get('LOW', 0)} | INFO {sev_counts.get('INFO', 0)}"
    )
    print()

    for r in results:
        print(f"[{r.status.value}] {r.check_id} ({r.benchmark_control_id or '-'}) {r.title}")
        print(f"  Severity: {r.severity.value} | Category: {r.category} | Evidence: {r.evidence_type}")
        if r.actual:
            print(f"  Actual: {r.actual}")
        if r.expected:
            print(f"  Expected: {r.expected}")
        if r.remediation:
            print(f"  Remediation: {r.remediation}")
        print()
