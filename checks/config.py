from .base import BaseChecker, CheckResult, Severity, Status


class RedisConfigChecker(BaseChecker):
    def run(self) -> list[CheckResult]:
        cfg = self.runner.config_get(
            "protected-mode",
            "bind",
            "port",
            "tls-port",
            "tls-replication",
            "tls-cluster",
            "appendonly",
            "save",
            "dir",
            "dbfilename",
            "aclfile",
        )
        acl_users = self.runner.acl_list()
        results = []

        protected = cfg.get("protected-mode")
        results.append(
            CheckResult(
                check_id="RD-CFG-001",
                title="Keep protected mode enabled unless compensating controls exist",
                status=Status.PASS if protected == "yes" else Status.FAIL if protected else Status.ERROR,
                severity=Severity.HIGH,
                benchmark_control_id="2.4",
                cis_id="draft-2.4",
                fedramp_control="SC-7",
                description="Redis protected mode helps guard against unintentionally exposed instances.",
                actual=protected or "unavailable",
                expected="yes",
                remediation="Set `protected-mode yes` unless documented compensating controls are in place.",
                references=["Redis security docs: protected mode"],
                category="Configuration",
                evidence_type="runtime-config",
            )
        )

        bind = cfg.get("bind", "")
        bind_safe = bind not in ("", "0.0.0.0", "*")
        results.append(
            CheckResult(
                check_id="RD-CFG-002",
                title="Bind Redis only to trusted interfaces",
                status=Status.PASS if bind_safe else Status.FAIL,
                severity=Severity.CRITICAL,
                benchmark_control_id="2.5",
                cis_id="draft-2.5",
                fedramp_control="SC-7",
                description="Broad network binding increases the risk of unintended Redis exposure.",
                actual=bind or "not explicitly set",
                expected="loopback or explicitly trusted interface(s)",
                remediation="Set `bind` to loopback or trusted interface addresses and pair with network-layer restrictions.",
                references=["Redis security docs: trusted clients, firewalling, bind"],
                category="Configuration",
                evidence_type="network-exposure",
            )
        )

        tls_port = cfg.get("tls-port", "0")
        results.append(
            CheckResult(
                check_id="RD-CFG-003",
                title="Enable TLS where Redis traffic crosses trust boundaries",
                status=Status.PASS if tls_port not in ("", "0") else Status.WARN,
                severity=Severity.MEDIUM,
                benchmark_control_id="3.1",
                cis_id="draft-3.1",
                fedramp_control="SC-8",
                description="TLS should protect Redis traffic when confidentiality or compliance requirements apply.",
                actual=f"tls-port={tls_port}",
                expected="non-zero TLS port when transport encryption is required",
                remediation="Configure `tls-port` and related certificate settings; consider disabling plaintext `port` where appropriate.",
                references=["Redis TLS documentation"],
                category="Transport Security",
                evidence_type="runtime-config",
            )
        )

        default_acl_line = next((line for line in acl_users if line.startswith("user default ")), "")
        default_open = ("nopass" in default_acl_line) or ("+@all" in default_acl_line and " on " in f" {default_acl_line} ")
        acl_status = Status.FAIL if default_open and acl_users else Status.PASS if acl_users else Status.ERROR
        results.append(
            CheckResult(
                check_id="RD-CFG-004",
                title="Restrict default-user broad access and prefer ACL-based least privilege",
                status=acl_status,
                severity=Severity.CRITICAL,
                benchmark_control_id="2.2",
                cis_id="draft-2.2",
                fedramp_control="AC-2",
                description="The default ACL user should not remain broadly permissive in regulated production deployments.",
                actual=default_acl_line or "ACL LIST unavailable",
                expected="no `nopass` broad default-user access; named least-privilege users preferred",
                remediation="Use ACLs to define named users and remove overly broad default-user access.",
                references=["Redis ACL documentation", "Redis security docs: ACLs preferred"],
                category="Authentication",
                evidence_type="runtime-config",
            )
        )

        dangerous_restricted = False
        if default_acl_line:
            dangerous_restricted = "-@all" in default_acl_line or ("+@all" not in default_acl_line)
        results.append(
            CheckResult(
                check_id="RD-CFG-005",
                title="Restrict dangerous administrative commands",
                status=Status.PASS if dangerous_restricted else Status.FAIL if default_acl_line else Status.ERROR,
                severity=Severity.HIGH,
                benchmark_control_id="2.3",
                cis_id="draft-2.3",
                fedramp_control="CM-7",
                description="Dangerous commands should not be broadly available to the default or application users.",
                actual=default_acl_line or "ACL LIST unavailable",
                expected="dangerous commands restricted via ACLs or equivalent approved control",
                remediation="Use ACLs to deny broad administrative command access to default/application users.",
                references=["Redis security docs: command restriction guidance", "Redis ACL documentation"],
                category="Configuration",
                evidence_type="runtime-config",
            )
        )

        appendonly = cfg.get("appendonly", "")
        save = cfg.get("save", "")
        persistence_ok = appendonly == "yes" or bool(save.strip())
        results.append(
            CheckResult(
                check_id="RD-CFG-006",
                title="Configure persistence intentionally",
                status=Status.PASS if persistence_ok else Status.WARN,
                severity=Severity.MEDIUM,
                benchmark_control_id="4.1",
                cis_id="draft-4.1",
                fedramp_control="CP-9",
                description="Redis persistence settings should be explicitly configured to match recovery and data durability needs.",
                actual=f"appendonly={appendonly or 'unset'}, save={save or 'unset'}",
                expected="documented AOF, RDB, both, or explicit decision for ephemeral use",
                remediation="Set and document persistence behavior appropriate to the workload and audit requirements.",
                references=["Redis configuration guidance"],
                category="Persistence",
                evidence_type="runtime-config",
            )
        )

        aclfile = cfg.get("aclfile", "")
        results.append(
            CheckResult(
                check_id="RD-CFG-007",
                title="Persist ACL configuration outside ad hoc runtime state",
                status=Status.PASS if aclfile else Status.WARN,
                severity=Severity.LOW,
                benchmark_control_id="2.2",
                cis_id="draft-2.2b",
                fedramp_control="CM-3",
                description="ACL configuration should be durable and reviewable rather than existing only as transient runtime state.",
                actual=aclfile or "no aclfile configured",
                expected="documented ACL persistence strategy",
                remediation="Use an ACL file or equivalent configuration-as-code approach to preserve and review user policy state.",
                references=["Redis ACL LIST documentation"],
                category="Authentication",
                evidence_type="runtime-config",
            )
        )

        return results
