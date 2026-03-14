from .base import BaseChecker, CheckResult, Severity, Status


class RedisRuntimeChecker(BaseChecker):
    def run(self) -> list[CheckResult]:
        info = self.runner.info("server")
        replication = self.runner.info("replication")
        results = []

        process_supervised = info.get("process_supervised", "unknown")
        redis_mode = info.get("redis_mode", "unknown")
        results.append(
            CheckResult(
                check_id="RD-RT-001",
                title="Collect Redis runtime server metadata for audit traceability",
                status=Status.PASS if info else Status.ERROR,
                severity=Severity.INFO,
                benchmark_control_id="8.0",
                cis_id="draft-8.0",
                fedramp_control="AU-3",
                description="Runtime metadata helps support repeatable annual audit evidence and traceability.",
                actual=f"redis_mode={redis_mode}, process_supervised={process_supervised}",
                expected="runtime metadata available",
                remediation="Ensure the scanner can collect server metadata through INFO or equivalent runtime evidence.",
                references=["Redis INFO documentation"],
                category="Runtime",
                evidence_type="runtime-config",
            )
        )

        role = replication.get("role", "unknown")
        results.append(
            CheckResult(
                check_id="RD-RT-002",
                title="Capture replication role for topology-aware assessment",
                status=Status.PASS if role != "unknown" else Status.WARN,
                severity=Severity.LOW,
                benchmark_control_id="5.1",
                cis_id="draft-5.1",
                fedramp_control="SC-7",
                description="Replication role should be known so replication-path controls can be assessed accurately.",
                actual=role,
                expected="master/replica role identified",
                remediation="Collect and review Redis replication topology before evaluating replication security controls.",
                references=["Redis INFO documentation"],
                category="Runtime",
                evidence_type="runtime-config",
            )
        )

        return results
