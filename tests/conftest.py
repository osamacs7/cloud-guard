import pytest
from unittest.mock import MagicMock


@pytest.fixture
def mock_aws_session():
    session = MagicMock()
    return session


@pytest.fixture
def sample_findings():
    from cloud_guard.models.entities import Severity
    from cloud_guard.scanners.base import ScanFinding

    return [
        ScanFinding(
            rule_id="CG-AWS-S3-001",
            title="S3 bucket public access not blocked",
            description="Bucket test-bucket has public access",
            severity=Severity.HIGH,
            resource_type="aws_s3_bucket",
            resource_id="test-bucket",
            compliance_control="CIS AWS 2.1.5",
        ),
        ScanFinding(
            rule_id="CG-AWS-EC2-001",
            title="Security group allows unrestricted SSH",
            description="SG sg-123 allows 0.0.0.0/0 on port 22",
            severity=Severity.CRITICAL,
            resource_type="aws_security_group",
            resource_id="sg-123",
            region="us-east-1",
            compliance_control="CIS AWS 5.2",
        ),
    ]
