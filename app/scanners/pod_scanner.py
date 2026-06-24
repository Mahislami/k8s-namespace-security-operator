from typing import List

from kubernetes import client

from app.models import SecurityFindingModel
from app.utils import image_uses_latest_or_no_tag


class PodScanner:
    """
    Scans Pods for Kubernetes security risks.

    Normal path:
      - scan_pod() scans one changed Pod.

    Consistency path:
      - scan_namespace() performs paginated namespace scanning.
      - This is only for startup/manual/periodic reconciliation.
    """

    def __init__(self, core_api: client.CoreV1Api, profile: dict, logger):
        self.core_api = core_api
        self.profile = profile or {}
        self.rules = self.profile.get("rules", {})
        self.logger = logger

    def scan_namespace(self, namespace: str) -> List[SecurityFindingModel]:
        findings = []
        continue_token = None

        while True:
            response = self.core_api.list_namespaced_pod(
                namespace=namespace,
                limit=500,
                _continue=continue_token,
            )

            for pod in response.items:
                findings.extend(self.scan_pod(pod))

            continue_token = response.metadata._continue
            if not continue_token:
                break

        return findings

    def scan_pod(self, pod) -> List[SecurityFindingModel]:
        findings = []

        namespace = pod.metadata.namespace
        pod_name = pod.metadata.name

        if self.rules.get("forbidHostNetwork", True) and pod.spec.host_network:
            findings.append(SecurityFindingModel(
                name=f"{namespace}-{pod_name}-host-network",
                severity="high",
                category="pod-security",
                namespace=namespace,
                resource_kind="Pod",
                resource_name=pod_name,
                issue="Pod is using hostNetwork",
                reason=["spec.hostNetwork=true"],
                recommendation="Set spec.hostNetwork=false unless explicitly required.",
                remediation_type="manifest-patch",
                remediation_patch={"spec": {"hostNetwork": False}},
            ))

        if self.rules.get("forbidHostPID", True) and pod.spec.host_pid:
            findings.append(SecurityFindingModel(
                name=f"{namespace}-{pod_name}-host-pid",
                severity="high",
                category="pod-security",
                namespace=namespace,
                resource_kind="Pod",
                resource_name=pod_name,
                issue="Pod is using hostPID",
                reason=["spec.hostPID=true"],
                recommendation="Set spec.hostPID=false.",
                remediation_type="manifest-patch",
                remediation_patch={"spec": {"hostPID": False}},
            ))

        if self.rules.get("forbidHostPath", True):
            for volume in pod.spec.volumes or []:
                if volume.host_path:
                    findings.append(SecurityFindingModel(
                        name=f"{namespace}-{pod_name}-hostpath-{volume.name}",
                        severity="high",
                        category="pod-security",
                        namespace=namespace,
                        resource_kind="Pod",
                        resource_name=pod_name,
                        issue=f"Pod uses hostPath volume '{volume.name}'",
                        reason=[f"volume.{volume.name}.hostPath is set"],
                        recommendation="Avoid hostPath volumes. Prefer PVCs, projected volumes, ConfigMaps, or Secrets.",
                        remediation_type="documentation",
                    ))

        if self.rules.get("flagDefaultServiceAccount", True):
            service_account = pod.spec.service_account_name or "default"
            if service_account == "default":
                findings.append(SecurityFindingModel(
                    name=f"{namespace}-{pod_name}-default-service-account",
                    severity="medium",
                    category="service-account",
                    namespace=namespace,
                    resource_kind="Pod",
                    resource_name=pod_name,
                    issue="Pod uses the default ServiceAccount",
                    reason=["spec.serviceAccountName is missing or default"],
                    recommendation="Create a dedicated least-privilege ServiceAccount for this workload.",
                    remediation_type="manifest-patch",
                    remediation_patch={"spec": {"serviceAccountName": "dedicated-service-account"}},
                ))

        containers = []
        containers.extend(pod.spec.containers or [])
        containers.extend(pod.spec.init_containers or [])

        for container in containers:
            findings.extend(self.scan_container_security(namespace, pod_name, container))

        return findings

    def scan_container_security(self, namespace: str, pod_name: str, container) -> List[SecurityFindingModel]:
        findings = []
        container_name = container.name
        security_context = container.security_context

        if self.rules.get("forbidPrivilegedContainers", True):
            if security_context and security_context.privileged is True:
                findings.append(SecurityFindingModel(
                    name=f"{namespace}-{pod_name}-{container_name}-privileged",
                    severity="critical",
                    category="pod-security",
                    namespace=namespace,
                    resource_kind="Pod",
                    resource_name=pod_name,
                    issue=f"Container '{container_name}' is running privileged",
                    reason=[f"container.{container_name}.securityContext.privileged=true"],
                    recommendation="Set securityContext.privileged=false.",
                    remediation_type="manifest-patch",
                    remediation_patch={
                        "spec": {
                            "containers": [
                                {
                                    "name": container_name,
                                    "securityContext": {"privileged": False},
                                }
                            ]
                        }
                    },
                ))

        if self.rules.get("requireRunAsNonRoot", True):
            if not security_context or security_context.run_as_non_root is not True:
                findings.append(SecurityFindingModel(
                    name=f"{namespace}-{pod_name}-{container_name}-run-as-non-root-missing",
                    severity="medium",
                    category="pod-security",
                    namespace=namespace,
                    resource_kind="Pod",
                    resource_name=pod_name,
                    issue=f"Container '{container_name}' does not enforce runAsNonRoot",
                    reason=[f"container.{container_name}.securityContext.runAsNonRoot missing or false"],
                    recommendation="Set securityContext.runAsNonRoot=true and use a non-zero runAsUser.",
                    remediation_type="manifest-patch",
                    remediation_patch={
                        "spec": {
                            "containers": [
                                {
                                    "name": container_name,
                                    "securityContext": {"runAsNonRoot": True},
                                }
                            ]
                        }
                    },
                ))

        if self.rules.get("forbidLatestImageTag", True):
            image = container.image
            if image_uses_latest_or_no_tag(image):
                findings.append(SecurityFindingModel(
                    name=f"{namespace}-{pod_name}-{container_name}-latest-image",
                    severity="low",
                    category="image-security",
                    namespace=namespace,
                    resource_kind="Pod",
                    resource_name=pod_name,
                    issue=f"Container '{container_name}' uses ':latest' or no explicit image tag",
                    reason=[f"image={image}"],
                    recommendation="Use a fixed immutable image tag or image digest.",
                    remediation_type="documentation",
                ))

        if self.rules.get("requireReadinessProbe", True):
            if container.readiness_probe is None:
                findings.append(SecurityFindingModel(
                    name=f"{namespace}-{pod_name}-{container_name}-missing-readiness-probe",
                    severity="low",
                    category="pod-security",
                    namespace=namespace,
                    resource_kind="Pod",
                    resource_name=pod_name,
                    issue=f"Container '{container_name}' has no readinessProbe",
                    reason=[f"container.{container_name}.readinessProbe is missing"],
                    recommendation="Add a readinessProbe so traffic is only sent when the container is ready.",
                    remediation_type="documentation",
                ))

        if self.rules.get("requireLivenessProbe", False):
            if container.liveness_probe is None:
                findings.append(SecurityFindingModel(
                    name=f"{namespace}-{pod_name}-{container_name}-missing-liveness-probe",
                    severity="low",
                    category="pod-security",
                    namespace=namespace,
                    resource_kind="Pod",
                    resource_name=pod_name,
                    issue=f"Container '{container_name}' has no livenessProbe",
                    reason=[f"container.{container_name}.livenessProbe is missing"],
                    recommendation="Add a livenessProbe so Kubernetes can restart unhealthy containers.",
                    remediation_type="documentation",
                ))

        resources = container.resources

        if self.rules.get("requireResourceRequests", True):
            if not resources or not resources.requests:
                findings.append(SecurityFindingModel(
                    name=f"{namespace}-{pod_name}-{container_name}-missing-resource-requests",
                    severity="low",
                    category="pod-security",
                    namespace=namespace,
                    resource_kind="Pod",
                    resource_name=pod_name,
                    issue=f"Container '{container_name}' has no resource requests",
                    reason=[f"container.{container_name}.resources.requests is missing"],
                    recommendation="Set CPU and memory requests for predictable scheduling.",
                    remediation_type="documentation",
                ))

        if self.rules.get("requireResourceLimits", True):
            if not resources or not resources.limits:
                findings.append(SecurityFindingModel(
                    name=f"{namespace}-{pod_name}-{container_name}-missing-resource-limits",
                    severity="low",
                    category="pod-security",
                    namespace=namespace,
                    resource_kind="Pod",
                    resource_name=pod_name,
                    issue=f"Container '{container_name}' has no resource limits",
                    reason=[f"container.{container_name}.resources.limits is missing"],
                    recommendation="Set CPU and memory limits to reduce resource-exhaustion risk.",
                    remediation_type="documentation",
                ))

        return findings
