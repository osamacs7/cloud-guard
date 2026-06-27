import boto3
from botocore.exceptions import ClientError

from cloud_guard.core.logging import logger
from cloud_guard.models.entities import Severity
from cloud_guard.scanners.base import BaseScanner, ScanFinding, ScanResult
from cloud_guard.scanners.registry import register_scanner


@register_scanner("aws")
class AWSScanner(BaseScanner):
    provider = "aws"

    def __init__(self, profile: str = "default", region: str = "us-east-1"):
        self.session = boto3.Session(profile_name=profile, region_name=region)
        self.region = region

    async def test_connection(self) -> bool:
        try:
            sts = self.session.client("sts")
            sts.get_caller_identity()
            return True
        except ClientError:
            return False

    async def scan(self, compliance_framework: str | None = None) -> ScanResult:
        result = ScanResult(provider="aws")

        checks = [
            self._check_s3_public_access,
            self._check_security_groups,
            self._check_iam_mfa,
            self._check_rds_encryption,
            self._check_cloudtrail,
            self._check_ebs_encryption,
            self._check_root_account_usage,
            self._check_password_policy,
            self._check_vpc_flow_logs,
            self._check_kms_key_rotation,
        ]

        for check in checks:
            try:
                findings = await check()
                result.findings.extend(findings)
                result.resources_scanned += 1
            except ClientError as e:
                result.errors.append(f"{check.__name__}: {e}")
                await logger.awarning("scanner_check_failed", check=check.__name__, error=str(e))

        return result

    async def _check_s3_public_access(self) -> list[ScanFinding]:
        findings = []
        s3 = self.session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            name = bucket["Name"]
            try:
                public_access = s3.get_public_access_block(Bucket=name)
                config = public_access["PublicAccessBlockConfiguration"]
                if not all([
                    config.get("BlockPublicAcls"),
                    config.get("IgnorePublicAcls"),
                    config.get("BlockPublicPolicy"),
                    config.get("RestrictPublicBuckets"),
                ]):
                    findings.append(ScanFinding(
                        rule_id="CG-AWS-S3-001",
                        title="S3 bucket public access not fully blocked",
                        description=f"Bucket {name} does not have all public access block settings enabled",
                        severity=Severity.HIGH,
                        resource_type="aws_s3_bucket",
                        resource_id=name,
                        remediation="Enable all S3 Block Public Access settings",
                        compliance_control="CIS AWS 2.1.5",
                    ))
            except ClientError:
                findings.append(ScanFinding(
                    rule_id="CG-AWS-S3-001",
                    title="S3 bucket missing public access block",
                    description=f"Bucket {name} has no public access block configuration",
                    severity=Severity.CRITICAL,
                    resource_type="aws_s3_bucket",
                    resource_id=name,
                    remediation="Enable S3 Block Public Access at the bucket level",
                    compliance_control="CIS AWS 2.1.5",
                ))

        return findings

    async def _check_security_groups(self) -> list[ScanFinding]:
        findings = []
        ec2 = self.session.client("ec2")
        sgs = ec2.describe_security_groups()["SecurityGroups"]

        for sg in sgs:
            for rule in sg.get("IpPermissions", []):
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        port = rule.get("FromPort", "all")
                        if port in (22, 3389, 3306, 5432, 27017):
                            findings.append(ScanFinding(
                                rule_id="CG-AWS-EC2-001",
                                title=f"Security group allows unrestricted access on port {port}",
                                description=f"Security group {sg['GroupId']} allows 0.0.0.0/0 on port {port}",
                                severity=Severity.CRITICAL,
                                resource_type="aws_security_group",
                                resource_id=sg["GroupId"],
                                region=self.region,
                                remediation=f"Restrict port {port} to specific IP ranges",
                                compliance_control="CIS AWS 5.2",
                            ))

        return findings

    async def _check_iam_mfa(self) -> list[ScanFinding]:
        findings = []
        iam = self.session.client("iam")
        users = iam.list_users()["Users"]

        for user in users:
            mfa = iam.list_mfa_devices(UserName=user["UserName"])
            if not mfa["MFADevices"]:
                findings.append(ScanFinding(
                    rule_id="CG-AWS-IAM-001",
                    title="IAM user without MFA",
                    description=f"User {user['UserName']} does not have MFA enabled",
                    severity=Severity.HIGH,
                    resource_type="aws_iam_user",
                    resource_id=user["UserName"],
                    remediation="Enable MFA for this IAM user",
                    compliance_control="CIS AWS 1.10",
                ))

        return findings

    async def _check_rds_encryption(self) -> list[ScanFinding]:
        findings = []
        rds = self.session.client("rds")
        instances = rds.describe_db_instances()["DBInstances"]

        for db in instances:
            if not db.get("StorageEncrypted"):
                findings.append(ScanFinding(
                    rule_id="CG-AWS-RDS-001",
                    title="RDS instance not encrypted at rest",
                    description=f"RDS instance {db['DBInstanceIdentifier']} storage is not encrypted",
                    severity=Severity.HIGH,
                    resource_type="aws_rds_instance",
                    resource_id=db["DBInstanceIdentifier"],
                    region=self.region,
                    remediation="Enable encryption at rest for the RDS instance",
                    compliance_control="CIS AWS 2.3.1",
                ))

        return findings

    async def _check_cloudtrail(self) -> list[ScanFinding]:
        findings = []
        ct = self.session.client("cloudtrail")
        trails = ct.describe_trails()["trailList"]

        if not trails:
            findings.append(ScanFinding(
                rule_id="CG-AWS-CT-001",
                title="CloudTrail not enabled",
                description="No CloudTrail trails are configured in this region",
                severity=Severity.CRITICAL,
                resource_type="aws_cloudtrail",
                resource_id="none",
                remediation="Enable CloudTrail with multi-region logging",
                compliance_control="CIS AWS 3.1",
            ))

        for trail in trails:
            if not trail.get("IsMultiRegionTrail"):
                findings.append(ScanFinding(
                    rule_id="CG-AWS-CT-002",
                    title="CloudTrail not multi-region",
                    description=f"Trail {trail['Name']} is not configured for multi-region",
                    severity=Severity.MEDIUM,
                    resource_type="aws_cloudtrail",
                    resource_id=trail["Name"],
                    remediation="Enable multi-region logging on this trail",
                    compliance_control="CIS AWS 3.1",
                ))

        return findings

    async def _check_ebs_encryption(self) -> list[ScanFinding]:
        findings = []
        ec2 = self.session.client("ec2")
        volumes = ec2.describe_volumes()["Volumes"]

        for vol in volumes:
            if not vol.get("Encrypted"):
                findings.append(ScanFinding(
                    rule_id="CG-AWS-EBS-001",
                    title="EBS volume not encrypted",
                    description=f"EBS volume {vol['VolumeId']} is not encrypted",
                    severity=Severity.MEDIUM,
                    resource_type="aws_ebs_volume",
                    resource_id=vol["VolumeId"],
                    region=self.region,
                    remediation="Enable default EBS encryption in the account",
                    compliance_control="CIS AWS 2.2.1",
                ))

        return findings

    async def _check_root_account_usage(self) -> list[ScanFinding]:
        findings = []
        iam = self.session.client("iam")
        summary = iam.get_account_summary()["SummaryMap"]

        if summary.get("AccountAccessKeysPresent", 0) > 0:
            findings.append(ScanFinding(
                rule_id="CG-AWS-IAM-002",
                title="Root account has active access keys",
                description="The root account has active access keys, which is a critical security risk",
                severity=Severity.CRITICAL,
                resource_type="aws_iam_root",
                resource_id="root",
                remediation="Remove root account access keys and use IAM users instead",
                compliance_control="CIS AWS 1.4",
            ))

        return findings

    async def _check_password_policy(self) -> list[ScanFinding]:
        findings = []
        iam = self.session.client("iam")

        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
            if policy.get("MinimumPasswordLength", 0) < 14:
                findings.append(ScanFinding(
                    rule_id="CG-AWS-IAM-003",
                    title="Weak password policy — minimum length under 14",
                    description=f"Password minimum length is {policy.get('MinimumPasswordLength', 0)}",
                    severity=Severity.MEDIUM,
                    resource_type="aws_iam_password_policy",
                    resource_id="password-policy",
                    remediation="Set minimum password length to 14 or more",
                    compliance_control="CIS AWS 1.8",
                ))
        except ClientError:
            findings.append(ScanFinding(
                rule_id="CG-AWS-IAM-003",
                title="No password policy configured",
                description="The account does not have a custom password policy",
                severity=Severity.HIGH,
                resource_type="aws_iam_password_policy",
                resource_id="password-policy",
                remediation="Configure a strong password policy",
                compliance_control="CIS AWS 1.8",
            ))

        return findings

    async def _check_vpc_flow_logs(self) -> list[ScanFinding]:
        findings = []
        ec2 = self.session.client("ec2")
        vpcs = ec2.describe_vpcs()["Vpcs"]

        for vpc in vpcs:
            flow_logs = ec2.describe_flow_logs(
                Filters=[{"Name": "resource-id", "Values": [vpc["VpcId"]]}]
            )["FlowLogs"]

            if not flow_logs:
                findings.append(ScanFinding(
                    rule_id="CG-AWS-VPC-001",
                    title="VPC flow logs not enabled",
                    description=f"VPC {vpc['VpcId']} does not have flow logs enabled",
                    severity=Severity.MEDIUM,
                    resource_type="aws_vpc",
                    resource_id=vpc["VpcId"],
                    region=self.region,
                    remediation="Enable VPC flow logs for network monitoring",
                    compliance_control="CIS AWS 3.9",
                ))

        return findings

    async def _check_kms_key_rotation(self) -> list[ScanFinding]:
        findings = []
        kms = self.session.client("kms")
        keys = kms.list_keys()["Keys"]

        for key in keys:
            try:
                rotation = kms.get_key_rotation_status(KeyId=key["KeyId"])
                if not rotation.get("KeyRotationEnabled"):
                    findings.append(ScanFinding(
                        rule_id="CG-AWS-KMS-001",
                        title="KMS key rotation not enabled",
                        description=f"KMS key {key['KeyId']} does not have automatic rotation enabled",
                        severity=Severity.MEDIUM,
                        resource_type="aws_kms_key",
                        resource_id=key["KeyId"],
                        remediation="Enable automatic key rotation for this KMS key",
                        compliance_control="CIS AWS 3.8",
                    ))
            except ClientError:
                pass

        return findings
