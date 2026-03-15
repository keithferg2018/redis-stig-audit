import io
import json
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from checks.auth import RedisAuthChecker
from checks.base import CheckResult, Severity, Status
from checks.config import RedisConfigChecker
from checks.container import RedisContainerChecker
from checks.runtime import RedisRuntimeChecker
from output.sarif import build_sarif
from output.bundle import build_bundle


class FakeRunner:
    def __init__(
        self,
        cfg=None,
        acl=None,
        info_sections=None,
        mode="direct",
        container=None,
        pod=None,
        namespace="default",
        docker_inspect=None,
        pod_inspect_data=None,
    ):
        self.cfg = cfg or {}
        self.acl = acl or []
        self.info_sections = info_sections or {}
        self.mode = mode
        self.container = container
        self.pod = pod
        self.namespace = namespace
        self._docker_inspect = docker_inspect  # dict (first element) or None
        self._pod_inspect = pod_inspect_data   # full kubectl get pod dict or None
        self.last_error = None
        self.command_log = []

    def config_get(self, *patterns):
        return {k: v for k, v in self.cfg.items() if k in patterns}

    def acl_list(self):
        return list(self.acl)

    def info(self, *sections):
        data = {}
        for section in sections:
            data.update(self.info_sections.get(section, {}))
        return data

    def container_inspect(self):
        return self._docker_inspect or {}

    def pod_inspect(self):
        return self._pod_inspect or {}

    def test_connection(self):
        return True

    def snapshot(self):
        return {
            "config": self.cfg,
            "acl_list": self.acl,
            "info_server": self.info_sections.get("server", {}),
            "info_replication": self.info_sections.get("replication", {}),
            "info_persistence": self.info_sections.get("persistence", {}),
            "command_log_tail": [],
            "last_error": None,
            "container_meta": self._docker_inspect or self._pod_inspect,
        }


class CheckCoverageTests(unittest.TestCase):
    def test_hardened_profile_yields_no_failures(self):
        runner = FakeRunner(
            cfg={
                "protected-mode": "yes",
                "bind": "127.0.0.1 -::1",
                "port": "0",
                "tls-port": "6379",
                "tls-replication": "yes",
                "tls-cluster": "yes",
                "appendonly": "yes",
                "save": "900 1",
                "aclfile": "/etc/redis/users.acl",
                "loglevel": "notice",
                "logfile": "",
                "syslog-enabled": "no",
            },
            acl=["user default on sanitize-payload ~* &* -@all +get +set +ping >hashed-secret"],
            info_sections={
                "server": {"redis_mode": "standalone", "process_supervised": "systemd"},
                "replication": {"role": "master"},
                "persistence": {"aof_enabled": "1", "rdb_last_bgsave_status": "ok"},
            },
        )
        results = []
        for checker in (RedisConfigChecker, RedisRuntimeChecker, RedisAuthChecker):
            results.extend(checker(runner).run())

        failing = [r for r in results if r.status.value in {"FAIL", "ERROR"}]
        self.assertEqual([], failing)

    def test_insecure_profile_surfaces_critical_findings(self):
        runner = FakeRunner(
            cfg={
                "protected-mode": "no",
                "bind": "0.0.0.0",
                "port": "6379",
                "tls-port": "0",
                "tls-replication": "no",
                "appendonly": "no",
                "save": "",
                "aclfile": "",
                "loglevel": "",
                "logfile": "",
                "syslog-enabled": "no",
            },
            acl=["user default on nopass ~* &* +@all"],
            info_sections={
                "server": {"redis_mode": "standalone", "process_supervised": "no"},
                "replication": {"role": "replica"},
                "persistence": {"aof_enabled": "0", "rdb_last_bgsave_status": "err"},
            },
        )
        results = []
        for checker in (RedisConfigChecker, RedisRuntimeChecker, RedisAuthChecker):
            results.extend(checker(runner).run())

        by_id = {r.check_id: r for r in results}
        self.assertEqual("FAIL", by_id["RD-AUTH-001"].status.value)
        self.assertEqual("FAIL", by_id["RD-CFG-002"].status.value)
        self.assertEqual("WARN", by_id["RD-CFG-008"].status.value)

    def test_cli_json_shape_contains_summary_and_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            outfile = Path(tmp) / "results.json"
            proc = subprocess.run(
                [
                    "python3",
                    "audit.py",
                    "--mode",
                    "direct",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "6399",
                    "--json",
                    str(outfile),
                    "--quiet",
                ],
                cwd=Path(__file__).resolve().parents[1],
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, proc.returncode, msg=proc.stderr)
            document = json.loads(outfile.read_text())
            self.assertIn("summary", document)
            self.assertIn("snapshot", document)
            self.assertIn("results", document)
            self.assertIn("risk_posture", document["summary"])
            self.assertIn("command_log_tail", document["snapshot"])


# ---------------------------------------------------------------------------
# Hardened docker inspect fixture
# ---------------------------------------------------------------------------
_HARDENED_DOCKER_INSPECT = {
    "Config": {"User": "999"},
    "HostConfig": {
        "Privileged": False,
        "CapAdd": None,
        "CapDrop": ["ALL"],
        "ReadonlyRootfs": True,
        "Memory": 536870912,   # 512 MiB
        "NanoCpus": 1000000000,  # 1 CPU
        "NetworkMode": "bridge",
        "PidMode": "",
        "IpcMode": "private",
    },
}

# Insecure docker inspect fixture — every control violated
_INSECURE_DOCKER_INSPECT = {
    "Config": {"User": ""},
    "HostConfig": {
        "Privileged": True,
        "CapAdd": ["SYS_ADMIN", "NET_ADMIN"],
        "CapDrop": [],
        "ReadonlyRootfs": False,
        "Memory": 0,
        "NanoCpus": 0,
        "NetworkMode": "host",
        "PidMode": "host",
        "IpcMode": "host",
    },
}

# Hardened kubectl pod fixture
_HARDENED_POD_INSPECT = {
    "spec": {
        "hostNetwork": False,
        "hostPID": False,
        "hostIPC": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 999},
        "containers": [
            {
                "name": "redis",
                "securityContext": {
                    "privileged": False,
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"], "add": []},
                },
                "resources": {
                    "limits": {"memory": "512Mi", "cpu": "1"},
                },
            }
        ],
    }
}

# Insecure kubectl pod fixture — every control violated
_INSECURE_POD_INSPECT = {
    "spec": {
        "hostNetwork": True,
        "hostPID": True,
        "hostIPC": True,
        "securityContext": {},
        "containers": [
            {
                "name": "redis",
                "securityContext": {
                    "privileged": True,
                    "allowPrivilegeEscalation": True,
                    "readOnlyRootFilesystem": False,
                    "capabilities": {"drop": [], "add": ["SYS_ADMIN"]},
                },
                "resources": {},
            }
        ],
    }
}


class ContainerCheckerDockerTests(unittest.TestCase):
    def _results(self, inspect_data):
        runner = FakeRunner(mode="docker", container="redis-test", docker_inspect=inspect_data)
        return {r.check_id: r for r in RedisContainerChecker(runner).run()}

    def test_hardened_docker_all_pass(self):
        by_id = self._results(_HARDENED_DOCKER_INSPECT)
        failing = [r for r in by_id.values() if r.status.value in {"FAIL", "ERROR", "WARN"}]
        self.assertEqual([], failing, msg=[(r.check_id, r.status, r.actual) for r in failing])

    def test_insecure_docker_surfaces_all_failures(self):
        by_id = self._results(_INSECURE_DOCKER_INSPECT)
        self.assertEqual("FAIL", by_id["RD-CONT-001"].status.value, "non-root check")
        self.assertEqual("FAIL", by_id["RD-CONT-002"].status.value, "privileged check")
        self.assertEqual("FAIL", by_id["RD-CONT-003"].status.value, "dangerous caps check")
        self.assertIn(by_id["RD-CONT-004"].status.value, {"WARN", "FAIL"}, "readonly rootfs")
        self.assertEqual("FAIL", by_id["RD-CONT-005"].status.value, "resource limits check")
        self.assertEqual("FAIL", by_id["RD-CONT-006"].status.value, "host namespaces check")

    def test_direct_mode_all_skip(self):
        runner = FakeRunner(mode="direct")
        results = RedisContainerChecker(runner).run()
        self.assertTrue(all(r.status.value == "SKIP" for r in results))
        self.assertEqual(6, len(results))

    def test_docker_inspect_failure_all_error(self):
        runner = FakeRunner(mode="docker", container="redis-test", docker_inspect=None)
        results = RedisContainerChecker(runner).run()
        self.assertTrue(all(r.status.value == "ERROR" for r in results))
        self.assertEqual(6, len(results))

    def test_dangerous_cap_add_only_no_drop_is_fail(self):
        inspect = {
            "Config": {"User": "999"},
            "HostConfig": {
                "Privileged": False,
                "CapAdd": ["NET_RAW"],
                "CapDrop": [],
                "ReadonlyRootfs": True,
                "Memory": 512 * 1024 * 1024,
                "NanoCpus": 1_000_000_000,
                "NetworkMode": "bridge",
                "PidMode": "",
                "IpcMode": "private",
            },
        }
        by_id = self._results(inspect)
        self.assertEqual("FAIL", by_id["RD-CONT-003"].status.value)

    def test_partial_resource_limits_is_warn(self):
        inspect = {
            "Config": {"User": "999"},
            "HostConfig": {
                "Privileged": False,
                "CapAdd": None,
                "CapDrop": ["ALL"],
                "ReadonlyRootfs": True,
                "Memory": 512 * 1024 * 1024,
                "NanoCpus": 0,   # CPU limit not set
                "NetworkMode": "bridge",
                "PidMode": "",
                "IpcMode": "private",
            },
        }
        by_id = self._results(inspect)
        self.assertEqual("WARN", by_id["RD-CONT-005"].status.value)

    def test_evidence_captured_for_each_check(self):
        by_id = self._results(_HARDENED_DOCKER_INSPECT)
        for r in by_id.values():
            self.assertTrue(len(r.evidence) >= 1, f"{r.check_id} has no evidence")


class ContainerCheckerKubectlTests(unittest.TestCase):
    def _results(self, pod_data):
        runner = FakeRunner(
            mode="kubectl",
            pod="redis-0",
            namespace="prod",
            pod_inspect_data=pod_data,
        )
        return {r.check_id: r for r in RedisContainerChecker(runner).run()}

    def test_hardened_kubectl_all_pass(self):
        by_id = self._results(_HARDENED_POD_INSPECT)
        failing = [r for r in by_id.values() if r.status.value in {"FAIL", "ERROR", "WARN"}]
        self.assertEqual([], failing, msg=[(r.check_id, r.status, r.actual) for r in failing])

    def test_insecure_kubectl_surfaces_all_failures(self):
        by_id = self._results(_INSECURE_POD_INSPECT)
        self.assertIn(by_id["RD-CONT-001"].status.value, {"FAIL", "WARN"}, "non-root check")
        self.assertEqual("FAIL", by_id["RD-CONT-002"].status.value, "privileged check")
        self.assertEqual("FAIL", by_id["RD-CONT-003"].status.value, "dangerous caps check")
        self.assertIn(by_id["RD-CONT-004"].status.value, {"WARN", "FAIL"}, "readonly rootfs")
        self.assertEqual("FAIL", by_id["RD-CONT-005"].status.value, "resource limits check")
        self.assertEqual("FAIL", by_id["RD-CONT-006"].status.value, "host namespaces check")

    def test_kubectl_inspect_failure_all_error(self):
        runner = FakeRunner(mode="kubectl", pod="redis-0", namespace="prod", pod_inspect_data=None)
        results = RedisContainerChecker(runner).run()
        self.assertTrue(all(r.status.value == "ERROR" for r in results))
        self.assertEqual(6, len(results))


# ---------------------------------------------------------------------------
# Helpers for output tests
# ---------------------------------------------------------------------------

def _fake_results():
    """Return two minimal CheckResult objects for output-layer tests."""
    return [
        CheckResult(
            check_id="RD-CFG-001",
            title="Protected mode enabled",
            status=Status.FAIL,
            severity=Severity.HIGH,
            benchmark_control_id="2.1",
            nist_800_53_controls=["AC-17"],
            fedramp_control="AC-17(1)",
            description="Redis protected-mode should be enabled.",
            actual="protected-mode: no",
            expected="protected-mode: yes",
            remediation="Set protected-mode yes in redis.conf.",
            references=["https://redis.io/docs/manual/security/"],
            category="network-exposure",
            evidence_type="runtime-config",
            evidence=[{"source": "config.protected-mode", "value": "no", "command": "CONFIG GET protected-mode"}],
        ),
        CheckResult(
            check_id="RD-AUTH-001",
            title="Require authenticated administrative access",
            status=Status.PASS,
            severity=Severity.CRITICAL,
            benchmark_control_id="2.2",
            nist_800_53_controls=["IA-2"],
            fedramp_control=None,
            description="Default user must not have nopass.",
            actual="nopass not present",
            expected="nopass absent",
            remediation="Configure a strong password for the default user.",
            references=[],
            category="authentication",
            evidence_type="runtime-config",
            evidence=[{"source": "default_acl", "value": "user default on ~* ..."}],
        ),
    ]


_FAKE_TARGET = {
    "mode": "direct",
    "display_name": "127.0.0.1:6379",
    "timestamp": "2026-03-14T00:00:00+00:00",
    "connected": False,
    "namespace": None,
    "container": None,
    "pod": None,
    "host": "127.0.0.1",
    "port": 6379,
    "last_error": None,
}

_FAKE_SUMMARY = {
    "status_counts": {"FAIL": 1, "PASS": 1},
    "severity_counts": {"HIGH": 1, "CRITICAL": 1},
    "actionable_findings": 1,
    "risk_posture": "HIGH RISK",
}

_FAKE_SNAPSHOT = {
    "config": {},
    "acl_list": [],
    "info_server": {},
    "info_replication": {},
    "info_persistence": {},
    "command_log_tail": [],
    "last_error": None,
    "container_meta": None,
}


# ---------------------------------------------------------------------------
# SARIF output tests
# ---------------------------------------------------------------------------

class SarifOutputTests(unittest.TestCase):
    def setUp(self):
        self.results = _fake_results()
        self.doc = build_sarif(self.results, _FAKE_TARGET, "redis-stig-audit", "0.3.0-draft")

    def test_sarif_top_level_shape(self):
        self.assertEqual("2.1.0", self.doc["version"])
        self.assertIn("$schema", self.doc)
        self.assertIn("runs", self.doc)
        self.assertEqual(1, len(self.doc["runs"]))

    def test_rules_deduplicated_one_per_check_id(self):
        rules = self.doc["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        self.assertEqual(len(rule_ids), len(set(rule_ids)), "Duplicate rule IDs")
        self.assertIn("RD-CFG-001", rule_ids)
        self.assertIn("RD-AUTH-001", rule_ids)

    def test_results_count_matches_input(self):
        sarif_results = self.doc["runs"][0]["results"]
        self.assertEqual(len(self.results), len(sarif_results))

    def test_fail_maps_to_error_level(self):
        sarif_results = self.doc["runs"][0]["results"]
        fail_entry = next(r for r in sarif_results if r["ruleId"] == "RD-CFG-001")
        self.assertEqual("error", fail_entry["level"])

    def test_pass_maps_to_none_level(self):
        sarif_results = self.doc["runs"][0]["results"]
        pass_entry = next(r for r in sarif_results if r["ruleId"] == "RD-AUTH-001")
        self.assertEqual("none", pass_entry["level"])

    def test_rule_tags_include_nist_and_benchmark(self):
        rules = {r["id"]: r for r in self.doc["runs"][0]["tool"]["driver"]["rules"]}
        tags = rules["RD-CFG-001"]["properties"]["tags"]
        self.assertIn("AC-17", tags)
        self.assertIn("FedRAMP:AC-17(1)", tags)
        self.assertIn("benchmark:2.1", tags)

    def test_result_has_location_with_artifact_uri(self):
        sarif_results = self.doc["runs"][0]["results"]
        loc = sarif_results[0]["locations"][0]["physicalLocation"]["artifactLocation"]
        self.assertTrue(loc["uri"].startswith("redis://"))

    def test_result_properties_carry_status_and_severity(self):
        sarif_results = self.doc["runs"][0]["results"]
        fail_entry = next(r for r in sarif_results if r["ruleId"] == "RD-CFG-001")
        props = fail_entry["properties"]
        self.assertEqual("FAIL", props["status"])
        self.assertEqual("HIGH", props["severity"])

    def test_rule_has_help_text_when_remediation_present(self):
        rules = {r["id"]: r for r in self.doc["runs"][0]["tool"]["driver"]["rules"]}
        self.assertIn("help", rules["RD-CFG-001"])
        self.assertIn("text", rules["RD-CFG-001"]["help"])

    def test_cli_sarif_flag_produces_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "results.sarif"
            proc = subprocess.run(
                [
                    "python3", "audit.py",
                    "--mode", "direct",
                    "--host", "127.0.0.1", "--port", "6399",
                    "--sarif", str(out),
                    "--quiet",
                ],
                cwd=Path(__file__).resolve().parents[1],
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, proc.returncode, msg=proc.stderr)
            doc = json.loads(out.read_text())
            self.assertEqual("2.1.0", doc["version"])
            self.assertIn("runs", doc)
            self.assertTrue(len(doc["runs"][0]["tool"]["driver"]["rules"]) > 0)


# ---------------------------------------------------------------------------
# Evidence bundle tests
# ---------------------------------------------------------------------------

class BundleOutputTests(unittest.TestCase):
    def setUp(self):
        self.results = _fake_results()
        document = {
            "schema_version": "2026-03-14",
            "tool": {"name": "redis-stig-audit", "version": "0.3.0-draft"},
            "target": _FAKE_TARGET,
            "summary": _FAKE_SUMMARY,
            "snapshot": _FAKE_SNAPSHOT,
            "results": [r.to_dict() for r in self.results],
        }
        self.raw = build_bundle(
            document, self.results, _FAKE_TARGET, _FAKE_SUMMARY,
            _FAKE_SNAPSHOT, "redis-stig-audit", "0.3.0-draft",
        )
        self.zf = zipfile.ZipFile(io.BytesIO(self.raw))

    def tearDown(self):
        self.zf.close()

    def test_bundle_is_valid_zip(self):
        self.assertIsInstance(self.zf, zipfile.ZipFile)

    def test_required_top_level_files_present(self):
        names = self.zf.namelist()
        for required in ("manifest.json", "results.json", "results.sarif", "snapshot.json", "summary.txt"):
            self.assertIn(required, names, f"Missing {required}")

    def test_evidence_file_per_check(self):
        names = self.zf.namelist()
        for r in self.results:
            self.assertIn(f"evidence/{r.check_id}.json", names)

    def test_manifest_lists_all_contents(self):
        manifest = json.loads(self.zf.read("manifest.json"))
        self.assertIn("contents", manifest)
        self.assertIn("manifest.json", manifest["contents"])
        self.assertIn("results.sarif", manifest["contents"])
        for r in self.results:
            self.assertIn(f"evidence/{r.check_id}.json", manifest["contents"])

    def test_manifest_has_tool_and_target(self):
        manifest = json.loads(self.zf.read("manifest.json"))
        self.assertEqual("redis-stig-audit", manifest["tool"]["name"])
        self.assertIn("target", manifest)

    def test_embedded_sarif_is_valid(self):
        sarif = json.loads(self.zf.read("results.sarif"))
        self.assertEqual("2.1.0", sarif["version"])
        self.assertIn("runs", sarif)

    def test_embedded_results_json_is_valid(self):
        doc = json.loads(self.zf.read("results.json"))
        self.assertIn("results", doc)
        self.assertIn("summary", doc)
        self.assertIn("snapshot", doc)

    def test_evidence_file_has_expected_fields(self):
        ev = json.loads(self.zf.read("evidence/RD-CFG-001.json"))
        for field in ("check_id", "title", "status", "severity", "actual", "expected", "evidence"):
            self.assertIn(field, ev, f"Missing field {field} in evidence file")

    def test_summary_txt_contains_target_and_findings(self):
        txt = self.zf.read("summary.txt").decode()
        self.assertIn("redis-stig-audit", txt)
        self.assertIn("127.0.0.1:6379", txt)
        self.assertIn("RD-CFG-001", txt)

    def test_cli_bundle_flag_produces_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "audit-bundle.zip"
            proc = subprocess.run(
                [
                    "python3", "audit.py",
                    "--mode", "direct",
                    "--host", "127.0.0.1", "--port", "6399",
                    "--bundle", str(out),
                    "--quiet",
                ],
                cwd=Path(__file__).resolve().parents[1],
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, proc.returncode, msg=proc.stderr)
            self.assertTrue(out.exists())
            with zipfile.ZipFile(str(out)) as zf:
                names = zf.namelist()
            self.assertIn("manifest.json", names)
            self.assertIn("results.sarif", names)
            self.assertIn("snapshot.json", names)


if __name__ == "__main__":
    unittest.main()
