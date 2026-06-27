from dataclasses import dataclass

from cloud_guard.core.logging import logger


@dataclass
class RemediationStep:
    description: str
    command: str | None = None
    is_manual: bool = False


@dataclass
class Playbook:
    rule_id: str
    title: str
    provider: str
    steps: list[RemediationStep]
    auto_remediable: bool = False


PLAYBOOKS: dict[str, Playbook] = {
    "CG-AWS-S3-001": Playbook(
        rule_id="CG-AWS-S3-001",
        title="Block S3 Public Access",
        provider="aws",
        auto_remediable=True,
        steps=[
            RemediationStep(
                description="Enable all S3 Block Public Access settings",
                command="aws s3api put-public-access-block --bucket {resource_id} "
                        "--public-access-block-configuration "
                        "BlockPublicAcls=true,IgnorePublicAcls=true,"
                        "BlockPublicPolicy=true,RestrictPublicBuckets=true",
            ),
            RemediationStep(
                description="Verify the setting was applied",
                command="aws s3api get-public-access-block --bucket {resource_id}",
            ),
        ],
    ),
    "CG-AWS-EC2-001": Playbook(
        rule_id="CG-AWS-EC2-001",
        title="Restrict Security Group Ingress",
        provider="aws",
        auto_remediable=False,
        steps=[
            RemediationStep(
                description="Identify the security group rules allowing 0.0.0.0/0",
                command="aws ec2 describe-security-groups --group-ids {resource_id}",
            ),
            RemediationStep(
                description="Remove the overly permissive rule and add restricted CIDR",
                is_manual=True,
            ),
        ],
    ),
    "CG-AWS-IAM-002": Playbook(
        rule_id="CG-AWS-IAM-002",
        title="Remove Root Access Keys",
        provider="aws",
        auto_remediable=False,
        steps=[
            RemediationStep(
                description="List root account access keys",
                command="aws iam list-access-keys --user-name root",
            ),
            RemediationStep(
                description="Delete root access keys (requires root login)",
                is_manual=True,
            ),
        ],
    ),
    "CG-K8S-POD-001": Playbook(
        rule_id="CG-K8S-POD-001",
        title="Remove Privileged Container Flag",
        provider="k8s",
        auto_remediable=False,
        steps=[
            RemediationStep(
                description="Edit the deployment to remove privileged: true from securityContext",
                is_manual=True,
            ),
            RemediationStep(
                description="Verify the pod restarts without privileged mode",
                command="kubectl get pod {resource_id} -o jsonpath='{.spec.containers[*].securityContext}'",
            ),
        ],
    ),
}


def get_playbook(rule_id: str) -> Playbook | None:
    return PLAYBOOKS.get(rule_id)


def get_remediation_commands(rule_id: str, resource_id: str) -> list[dict]:
    playbook = get_playbook(rule_id)
    if not playbook:
        return []

    return [
        {
            "step": i + 1,
            "description": step.description,
            "command": step.command.format(resource_id=resource_id) if step.command else None,
            "is_manual": step.is_manual,
        }
        for i, step in enumerate(playbook.steps)
    ]
