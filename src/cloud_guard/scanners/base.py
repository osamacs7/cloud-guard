from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from cloud_guard.models.entities import Severity


@dataclass
class ScanFinding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    resource_type: str
    resource_id: str
    region: str | None = None
    remediation: str | None = None
    compliance_control: str | None = None


@dataclass
class ScanResult:
    provider: str
    findings: list[ScanFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    resources_scanned: int = 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)


class BaseScanner(ABC):
    provider: str

    @abstractmethod
    async def scan(self, compliance_framework: str | None = None) -> ScanResult: ...

    @abstractmethod
    async def test_connection(self) -> bool: ...
