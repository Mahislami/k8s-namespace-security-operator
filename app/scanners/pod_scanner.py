from typing import List
import re

from kubernetes import client

from app.models import SecurityFindingModel
from app.utils import image_uses_latest_or_no_tag


class PodScanner:
    """
    Scans Pods for Kubernetes security risks.

    Important design:
    - Controlled Pods are skipped in namespace scans because their security
      belongs to the owning workload template.
    - Short-lived generated Pods are NOT skipped.
    - Timestamped generated Pod names are normalized so repeated CronJob/Job
      executions do not create endless unique findings.
    """

    CONTROLLED_OWNER_KINDS = {
        "ReplicaSet",
        "DaemonSet",
        "StatefulSet",
        "Job",
        "CronJob",
    }

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
                if self.is_controlled_pod(pod):
                    continue

                findings.extend(self.scan_pod(pod))

            continue_token = response.metadata._continue
            if not continue_token:
                break

        return findings

    def is_controlled_pod(self, pod) -> bool:
        owners = pod.metadata.owner_references or []
        return any(owner.kind in self.CONTROLLED_OWNER_KINDS for owner in owners)

    def normalize_generated_name(self, name: str) -> str:
        """
        Examples:
        external-dns-google-1782423349 -> external-dns-google
        network-prober-nur-1782423109 -> network-prober-nur
        dns-hecant-golang-1782423110 -> dns-hecant-golang
        """
        if not name:
            return ""

        return re.sub(r"-\d{8,}$", "", name)

    def observed_reason(self, original_name: str, normalized_name: str) -> List[str]:
        if original_name != normalized_name:
            return [f"observedPod={original_name}"]
        return []

    def scan_pod(self, pod) -> List[SecurityFindingModel]:
        findings = []

        namespace = pod.metadata.namespace
        pod_name = pod.metadata.name
        resource_name = self.normalize_generated_name(pod_name)
        base_reason = self.observed_reason(pod_name, resource_name)

        if self.rules.get("forbidHostNetwork", True) and pod.spec.host_network:
            findings.append(SecurityFindingModel(
                name=f"{namespace}-{resource_name}-host-network",
                severity="high",
                category="pod-security",
                namespace=namespace,
                resource_kind="Pod",
                resource_name=resource_name,
                issue="Pod is using hostNetwork",
                reason=base_reason + ["spec.hostNetwork=true"],
                recommendation="Set spec.hostNetwork=false unless explicitly required.",
                remediation_type="manifest-patch",
                remediation_patch={"spec": {"hostNetwork": False}},
            ))

        if self.rules.get("forbidHostPID", True) and pod.spec.host_pid:
            findings.append(SecurityFindingModel(
                name=f"{namespace}-{resource_name}-host-pid",
                severity="high",
                category="pod-security",
                namespace=namespace,
                resource_kind="Pod",
                resource_name=resource_name,
                issue="Pod is using hostPID",
                reason=base_reason + ["spec.hostPID=true"],
                recommendation="Set spec.hostPID=false.",
                remediation_type="manifest-patch",
                remediation_patch={"spec": {"hostPID": False}},
            ))

        if self.rules.get("forbidHostPath", True):
            for volume in pod.spec.volumes or []:
                if volume.host_path:
                    findings.append(SecurityFindingModel(
                        name=f"{namespace}-{resource_name}-hostpath-{volume.name}",
                        severity="high",
                        category="pod-security",
                        namespace=namespace,
                        resource_kind="Pod",
                        resource_name=resource_name,
                        issue=f"Pod uses hostPath volume '{volume.name}'",
                        reason=base_reason + [f"volume.{volume.name}.hostPath is set"],
                        recommendation="Avoid hostPath volumes. Prefer PVCs, projected volumes, ConfigMaps, or Secrets.",
                        remediation_type="documentation",
                    ))

        if self.rules.get("flagDefaultServiceAccount", True):
            service_account = pod.spec.service_account_name or "default"

            if service_account == "default":
                findings.append(SecurityFindingModel(
                    name=f"{namespace}-{resource_name}-default-service-account",
                    severity="medium",
                    category="service-account",
                    namespace=namespace,
                    resource_kind="Pod",
                    resource_name=resource_name,
                    issue="Pod uses the default ServiceAccount",
                    reason=base_reason + ["spec.serviceAccountName is missing or default"],
                    recommendation="Create a dedicated least-privilege ServiceAccount for this workload.",
                    remediation_type="manifest-patch",
                    remediation_patch={"spec": {"serviceAccountName": "dedicated-service-account"}},
                ))

        containers = []
        containers.extend(pod.spec.containers or [])
        containers.extend(pod.spec.init_containers or [])

        for container in containers:
            findings.extend(
                self.scan_container_security(
                    namespace=namespace,
                    pod_name=resource_name,
                    container=container,
                    base_reason=base_reason,
                )
            )

        return findings

    def scan_container_security(
        self,
        namespace: str,
        pod_name: str,
        container,
        base_reason: List[str],
    ) -> List[SecurityFindingModel]:
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
                    reason=base_reason + [f"container.{container_name}.securityContext.privileged=true"],
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
                    reason=base_reason + [f"container.{container_name}.securityContext.runAsNonRoot missing or false"],
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
                    reason=base_reason + [f"image={image}"],
                    recommendation="Use a fixed immutable image tag or image digest.",
                    remediation_type="documentation",
                ))

        return findings
