from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

from cloud_guard.core.logging import logger
from cloud_guard.models.entities import Severity
from cloud_guard.scanners.base import BaseScanner, ScanFinding, ScanResult
from cloud_guard.scanners.registry import register_scanner


@register_scanner("k8s")
class KubernetesScanner(BaseScanner):
    provider = "k8s"

    def __init__(self, kubeconfig: str | None = None):
        try:
            if kubeconfig:
                config.load_kube_config(config_file=kubeconfig)
            else:
                config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()

        self.core_v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()
        self.rbac_v1 = client.RbacAuthorizationV1Api()
        self.networking_v1 = client.NetworkingV1Api()

    async def test_connection(self) -> bool:
        try:
            self.core_v1.get_api_resources()
            return True
        except ApiException:
            return False

    async def scan(self, compliance_framework: str | None = None) -> ScanResult:
        result = ScanResult(provider="k8s")

        checks = [
            self._check_privileged_containers,
            self._check_root_containers,
            self._check_resource_limits,
            self._check_network_policies,
            self._check_default_service_accounts,
            self._check_host_namespaces,
        ]

        for check in checks:
            try:
                findings = await check()
                result.findings.extend(findings)
                result.resources_scanned += 1
            except ApiException as e:
                result.errors.append(f"{check.__name__}: {e.reason}")
                await logger.awarning("k8s_check_failed", check=check.__name__, error=e.reason)

        return result

    async def _check_privileged_containers(self) -> list[ScanFinding]:
        findings = []
        pods = self.core_v1.list_pod_for_all_namespaces()

        for pod in pods.items:
            for container in pod.spec.containers or []:
                sc = container.security_context
                if sc and sc.privileged:
                    findings.append(ScanFinding(
                        rule_id="CG-K8S-POD-001",
                        title="Privileged container detected",
                        description=f"Container {container.name} in pod {pod.metadata.name} runs in privileged mode",
                        severity=Severity.CRITICAL,
                        resource_type="k8s_pod",
                        resource_id=f"{pod.metadata.namespace}/{pod.metadata.name}",
                        remediation="Remove privileged: true from the container security context",
                        compliance_control="CIS K8s 5.2.1",
                    ))

        return findings

    async def _check_root_containers(self) -> list[ScanFinding]:
        findings = []
        pods = self.core_v1.list_pod_for_all_namespaces()

        for pod in pods.items:
            for container in pod.spec.containers or []:
                sc = container.security_context
                if not sc or sc.run_as_non_root is not True:
                    findings.append(ScanFinding(
                        rule_id="CG-K8S-POD-002",
                        title="Container may run as root",
                        description=f"Container {container.name} in pod {pod.metadata.name} does not enforce non-root",
                        severity=Severity.HIGH,
                        resource_type="k8s_pod",
                        resource_id=f"{pod.metadata.namespace}/{pod.metadata.name}",
                        remediation="Set runAsNonRoot: true in the container security context",
                        compliance_control="CIS K8s 5.2.6",
                    ))

        return findings

    async def _check_resource_limits(self) -> list[ScanFinding]:
        findings = []
        pods = self.core_v1.list_pod_for_all_namespaces()

        for pod in pods.items:
            if pod.metadata.namespace in ("kube-system", "kube-public"):
                continue
            for container in pod.spec.containers or []:
                if not container.resources or not container.resources.limits:
                    findings.append(ScanFinding(
                        rule_id="CG-K8S-POD-003",
                        title="Container missing resource limits",
                        description=f"Container {container.name} in pod {pod.metadata.name} has no resource limits",
                        severity=Severity.MEDIUM,
                        resource_type="k8s_pod",
                        resource_id=f"{pod.metadata.namespace}/{pod.metadata.name}",
                        remediation="Define CPU and memory limits for this container",
                        compliance_control="CIS K8s 5.4.1",
                    ))

        return findings

    async def _check_network_policies(self) -> list[ScanFinding]:
        findings = []
        namespaces = self.core_v1.list_namespace()

        for ns in namespaces.items:
            if ns.metadata.name in ("kube-system", "kube-public", "kube-node-lease", "default"):
                continue
            policies = self.networking_v1.list_namespaced_network_policy(ns.metadata.name)
            if not policies.items:
                findings.append(ScanFinding(
                    rule_id="CG-K8S-NET-001",
                    title="Namespace missing network policies",
                    description=f"Namespace {ns.metadata.name} has no network policies",
                    severity=Severity.MEDIUM,
                    resource_type="k8s_namespace",
                    resource_id=ns.metadata.name,
                    remediation="Define network policies to restrict pod-to-pod traffic",
                    compliance_control="CIS K8s 5.3.2",
                ))

        return findings

    async def _check_default_service_accounts(self) -> list[ScanFinding]:
        findings = []
        pods = self.core_v1.list_pod_for_all_namespaces()

        for pod in pods.items:
            if pod.metadata.namespace in ("kube-system", "kube-public"):
                continue
            if pod.spec.service_account_name == "default":
                findings.append(ScanFinding(
                    rule_id="CG-K8S-SA-001",
                    title="Pod using default service account",
                    description=f"Pod {pod.metadata.name} uses the default service account",
                    severity=Severity.MEDIUM,
                    resource_type="k8s_pod",
                    resource_id=f"{pod.metadata.namespace}/{pod.metadata.name}",
                    remediation="Create and assign a dedicated service account",
                    compliance_control="CIS K8s 5.1.5",
                ))

        return findings

    async def _check_host_namespaces(self) -> list[ScanFinding]:
        findings = []
        pods = self.core_v1.list_pod_for_all_namespaces()

        for pod in pods.items:
            issues = []
            if pod.spec.host_network:
                issues.append("hostNetwork")
            if pod.spec.host_pid:
                issues.append("hostPID")
            if pod.spec.host_ipc:
                issues.append("hostIPC")

            if issues:
                findings.append(ScanFinding(
                    rule_id="CG-K8S-POD-004",
                    title="Pod using host namespaces",
                    description=f"Pod {pod.metadata.name} uses host namespaces: {', '.join(issues)}",
                    severity=Severity.HIGH,
                    resource_type="k8s_pod",
                    resource_id=f"{pod.metadata.namespace}/{pod.metadata.name}",
                    remediation="Disable host namespace sharing unless absolutely required",
                    compliance_control="CIS K8s 5.2.2",
                ))

        return findings
