#!/usr/bin/env python3
"""Runner helpers for redis-stig-audit."""
from dataclasses import dataclass, field
import json
import shlex
import subprocess


@dataclass
class RedisRunner:
    mode: str = "docker"
    container: str | None = None
    pod: str | None = None
    namespace: str = "default"
    host: str = "127.0.0.1"
    port: int = 6379
    password: str | None = None
    verbose: bool = False
    last_error: str | None = None
    command_log: list[dict] = field(default_factory=list)

    def _base_cli(self) -> list[str]:
        if self.mode == "direct":
            cmd = ["redis-cli", "-h", self.host, "-p", str(self.port), "--raw"]
            if self.password:
                cmd.extend(["-a", self.password])
            return cmd
        if self.mode == "docker":
            if not self.container:
                raise ValueError("--container is required for docker mode")
            cmd = ["docker", "exec", self.container, "redis-cli", "--raw"]
            if self.password:
                cmd.extend(["-a", self.password])
            return cmd
        if self.mode == "kubectl":
            if not self.pod:
                raise ValueError("--pod is required for kubectl mode")
            cmd = ["kubectl", "exec", "-n", self.namespace, self.pod, "--", "redis-cli", "--raw"]
            if self.password:
                cmd.extend(["-a", self.password])
            return cmd
        raise ValueError(f"Unsupported mode: {self.mode}")

    def exec(self, command: list[str]) -> subprocess.CompletedProcess:
        if self.verbose:
            print("[runner]", shlex.join(command))
        try:
            res = subprocess.run(command, capture_output=True, text=True)
        except FileNotFoundError as exc:
            self.last_error = str(exc)
            self.command_log.append(
                {"command": shlex.join(command), "returncode": 127, "stdout": "", "stderr": str(exc)}
            )
            return subprocess.CompletedProcess(command, 127, "", str(exc))
        self.last_error = res.stderr.strip() or None if res.returncode != 0 else None
        self.command_log.append(
            {
                "command": shlex.join(command),
                "returncode": res.returncode,
                "stdout": res.stdout.strip(),
                "stderr": res.stderr.strip(),
            }
        )
        return res

    def redis_cli(self, *args: str) -> subprocess.CompletedProcess:
        return self.exec(self._base_cli() + list(args))

    def test_connection(self) -> bool:
        res = self.redis_cli("PING")
        return res.returncode == 0 and "PONG" in res.stdout

    def config_get(self, *patterns: str) -> dict[str, str]:
        out = {}
        for pattern in patterns:
            res = self.redis_cli("CONFIG", "GET", pattern)
            if res.returncode != 0:
                continue
            lines = [line for line in res.stdout.splitlines() if line.strip()]
            for i in range(0, len(lines), 2):
                key = lines[i]
                val = lines[i + 1] if i + 1 < len(lines) else ""
                out[key] = val
        return out

    def acl_list(self) -> list[str]:
        res = self.redis_cli("ACL", "LIST")
        if res.returncode != 0:
            return []
        return [line.strip() for line in res.stdout.splitlines() if line.strip()]

    def info(self, *sections: str) -> dict[str, str]:
        cmd = ["INFO"]
        cmd.extend(sections)
        res = self.redis_cli(*cmd)
        if res.returncode != 0:
            return {}
        data = {}
        for line in res.stdout.splitlines():
            if not line or line.startswith("#") or ":" not in line:
                continue
            k, v = line.split(":", 1)
            data[k.strip()] = v.strip()
        return data

    def container_inspect(self) -> dict:
        """Return parsed `docker inspect` data for the configured container, or {}."""
        if self.mode != "docker" or not self.container:
            return {}
        res = self.exec(["docker", "inspect", self.container])
        if res.returncode != 0:
            return {}
        try:
            data = json.loads(res.stdout)
            return data[0] if isinstance(data, list) and data else {}
        except (json.JSONDecodeError, IndexError):
            return {}

    def pod_inspect(self) -> dict:
        """Return parsed `kubectl get pod -o json` data for the configured pod, or {}."""
        if self.mode != "kubectl" or not self.pod:
            return {}
        res = self.exec(
            ["kubectl", "get", "pod", "-n", self.namespace, self.pod, "-o", "json"]
        )
        if res.returncode != 0:
            return {}
        try:
            return json.loads(res.stdout)
        except json.JSONDecodeError:
            return {}

    def snapshot(self) -> dict:
        container_meta: dict | None = None
        if self.mode == "docker":
            container_meta = self.container_inspect() or None
        elif self.mode == "kubectl":
            container_meta = self.pod_inspect() or None

        return {
            "config": self.config_get(
                "protected-mode",
                "bind",
                "port",
                "tls-port",
                "tls-replication",
                "tls-cluster",
                "appendonly",
                "appenddirname",
                "save",
                "dir",
                "dbfilename",
                "aclfile",
                "loglevel",
                "logfile",
                "syslog-enabled",
            ),
            "acl_list": self.acl_list(),
            "info_server": self.info("server"),
            "info_replication": self.info("replication"),
            "info_persistence": self.info("persistence"),
            "command_log_tail": self.command_log[-10:],
            "last_error": self.last_error,
            "container_meta": container_meta,
        }
