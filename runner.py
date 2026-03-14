#!/usr/bin/env python3
"""Runner helpers for redis-stig-audit."""
from dataclasses import dataclass
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
        return subprocess.run(command, capture_output=True, text=True)

    def redis_cli(self, *args: str) -> subprocess.CompletedProcess:
        return self.exec(self._base_cli() + list(args))

    def test_connection(self) -> bool:
        res = self.redis_cli("PING")
        return res.returncode == 0 and "PONG" in res.stdout

    def config_get(self, *patterns: str) -> dict[str, str]:
        res = self.redis_cli("CONFIG", "GET", *patterns)
        if res.returncode != 0:
            return {}
        lines = [line for line in res.stdout.splitlines() if line.strip()]
        out = {}
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

    def command_available(self, *args: str) -> bool:
        res = self.redis_cli(*args)
        return res.returncode == 0

    def snapshot(self) -> dict:
        return {
            "config": self.config_get("protected-mode", "bind", "port", "tls-port", "tls-replication", "tls-cluster"),
            "acl_list": self.acl_list(),
            "info_server": self.info("server"),
            "info_replication": self.info("replication"),
        }
