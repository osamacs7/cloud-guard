import pytest
from pathlib import Path

from cloud_guard.compliance.engine import ComplianceEngine, ComplianceFramework
from cloud_guard.models.entities import Severity
from cloud_guard.scanners.base import ScanFinding, ScanResult


class TestComplianceFramework:
    @pytest.fixture
    def framework(self, tmp_path):
        policy = tmp_path / "test.yml"
        policy.write_text("""
name: test-framework
version: "1.0"
controls:
  - id: "CTRL-1"
    title: "Test control 1"
    severity: high
  - id: "CTRL-2"
    title: "Test control 2"
    severity: medium
  - id: "CTRL-3"
    title: "Test control 3"
    severity: low
""")
        return ComplianceFramework.from_yaml(policy)

    def test_load_framework(self, framework):
        assert framework.name == "test-framework"
        assert len(framework.controls) == 3

    def test_full_compliance(self, framework):
        result = ScanResult(provider="aws")
        report = framework.evaluate(result)
        assert report["score"] == 100.0
        assert report["passed"] == 3
        assert report["failed"] == 0

    def test_partial_compliance(self, framework):
        result = ScanResult(
            provider="aws",
            findings=[
                ScanFinding(
                    rule_id="X",
                    title="fail",
                    description="fail",
                    severity=Severity.HIGH,
                    resource_type="t",
                    resource_id="r",
                    compliance_control="CTRL-1",
                ),
            ],
        )
        report = framework.evaluate(result)
        assert report["failed"] == 1
        assert report["passed"] == 2
        assert report["score"] == pytest.approx(66.7, abs=0.1)


class TestComplianceEngine:
    def test_load_policies(self):
        engine = ComplianceEngine(policies_dir=Path("policies"))
        assert len(engine.frameworks) >= 1
