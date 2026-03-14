from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Status(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"
    ERROR = "ERROR"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class CheckResult:
    check_id: str
    title: str
    status: Status
    severity: Severity
    benchmark_control_id: Optional[str] = None
    cis_id: Optional[str] = None
    fedramp_control: Optional[str] = None
    description: str = ""
    actual: str = ""
    expected: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    category: str = ""
    evidence_type: str = "runtime-config"

    def to_dict(self):
        return {
            "check_id": self.check_id,
            "title": self.title,
            "status": self.status.value,
            "severity": self.severity.value,
            "benchmark_control_id": self.benchmark_control_id,
            "cis_id": self.cis_id,
            "fedramp_control": self.fedramp_control,
            "description": self.description,
            "actual": self.actual,
            "expected": self.expected,
            "remediation": self.remediation,
            "references": self.references,
            "category": self.category,
            "evidence_type": self.evidence_type,
        }


class BaseChecker:
    def __init__(self, runner):
        self.runner = runner

    def run(self) -> list[CheckResult]:
        raise NotImplementedError
