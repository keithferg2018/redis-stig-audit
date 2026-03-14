from .base import BaseChecker, CheckResult, Severity, Status


class RedisAuthChecker(BaseChecker):
    def run(self) -> list[CheckResult]:
        acl_lines = self.runner.acl_list()
        if not acl_lines:
            return [
                CheckResult(
                    check_id="RD-AUTH-001",
                    title="Require authenticated administrative access",
                    status=Status.ERROR,
                    severity=Severity.CRITICAL,
                    benchmark_control_id="2.1",
                    cis_id="draft-2.1",
                    fedramp_control="AC-6",
                    description="Authentication posture could not be determined because ACL data was unavailable.",
                    actual="ACL LIST unavailable",
                    expected="administrative access requires authentication",
                    remediation="Verify Redis is reachable with appropriate credentials and inspect ACL/auth configuration.",
                    references=["Redis security docs", "Redis ACL documentation"],
                    category="Authentication",
                    evidence_type="runtime-config",
                )
            ]

        default_acl = next((line for line in acl_lines if line.startswith("user default ")), "")
        requires_auth = "nopass" not in default_acl
        return [
            CheckResult(
                check_id="RD-AUTH-001",
                title="Require authenticated administrative access",
                status=Status.PASS if requires_auth else Status.FAIL,
                severity=Severity.CRITICAL,
                benchmark_control_id="2.1",
                cis_id="draft-2.1",
                fedramp_control="AC-6",
                description="Administrative access should not be available without authentication.",
                actual=default_acl,
                expected="no `nopass` default access",
                remediation="Require authentication via ACL users or an approved authenticated access pattern.",
                references=["Redis security docs: authentication", "Redis ACL documentation"],
                category="Authentication",
                evidence_type="runtime-config",
            )
        ]
