import pytest

from cloud_guard.models.entities import Severity
from cloud_guard.scanners.base import ScanFinding, ScanResult


class TestScanResult:
    def test_empty_result(self):
        result = ScanResult(provider="aws")
        assert result.critical_count == 0
        assert result.high_count == 0
        assert result.resources_scanned == 0

    def test_severity_counts(self, sample_findings):
        result = ScanResult(provider="aws", findings=sample_findings)
        assert result.critical_count == 1
        assert result.high_count == 1

    def test_errors_tracked(self):
        result = ScanResult(provider="aws", errors=["check failed"])
        assert len(result.errors) == 1


class TestScanFinding:
    def test_finding_creation(self):
        finding = ScanFinding(
            rule_id="TEST-001",
            title="Test finding",
            description="A test finding",
            severity=Severity.HIGH,
            resource_type="test",
            resource_id="test-123",
        )
        assert finding.rule_id == "TEST-001"
        assert finding.severity == Severity.HIGH
        assert finding.region is None
        assert finding.remediation is None
