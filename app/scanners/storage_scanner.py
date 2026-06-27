from typing import List, Set

from app.models import SecurityFindingModel
from app.utils import to_k8s_name


class StorageScanner:
    """
    Storage posture scanner.

    Checks:
    - standalone Pods using hostPath
    - PVCs without storageClassName
    - PVCs not mounted by current Pods
    """

    def __init__(self, core_api, profile: dict, logger):
        self.core_api = core_api
        self.profile = profile or {}
        self.rules = self.profile.get("rules", {})
        self.logger = logger

    def scan_namespace(self, namespace: str) -> List[SecurityFindingModel]:
        findings = []
        findings.extend(self.scan_pod_storage(namespace))
        findings.extend(self.scan_pvcs(namespace))
        return findings

    def scan_pod_storage(self, namespace: str) -> List[SecurityFindingModel]:
        findings = []

        try:
            pods = self.core_api.list_namespaced_pod(namespace=namespace).items
        except Exception as exc:
            self.logger.warning(
                f"Failed to list Pods for storage scanning in {namespace}: {exc}"
            )
            return findings

        for pod in pods:
            if pod.metadata.owner_references:
                continue

            for volume in pod.spec.volumes or []:
                if volume.host_path:
                    findings.append(
                        self.finding(
                            namespace=namespace,
                            resource_kind="Pod",
                            resource_name=pod.metadata.name,
                            suffix=f"hostpath-{volume.name}",
                            severity="high",
                            issue="Pod uses hostPath volume.",
                            reason=[
                                f"Volume '{volume.name}' mounts host path '{volume.host_path.path}'.",
                                "hostPath can expose node filesystem data to containers.",
                            ],
                            recommendation="Avoid hostPath volumes unless strictly required. Use PVCs or projected volumes instead.",
                        )
                    )

        return findings

    def scan_pvcs(self, namespace: str) -> List[SecurityFindingModel]:
        findings = []

        try:
            pvcs = self.core_api.list_namespaced_persistent_volume_claim(
                namespace=namespace
            ).items
        except Exception as exc:
            self.logger.warning(f"Failed to list PVCs in {namespace}: {exc}")
            return findings

        used_pvcs = self.collect_used_pvcs(namespace)

        for pvc in pvcs:
            name = pvc.metadata.name

            if not pvc.spec.storage_class_name:
                findings.append(
                    self.finding(
                        namespace=namespace,
                        resource_kind="PersistentVolumeClaim",
                        resource_name=name,
                        suffix="missing-storage-class",
                        severity="medium",
                        issue="PVC does not specify a storageClassName.",
                        reason=[
                            "PVCs without explicit storageClassName may bind to unexpected default storage.",
                        ],
                        recommendation="Set storageClassName explicitly to control storage backend and policy.",
                    )
                )

            if name not in used_pvcs:
                findings.append(
                    self.finding(
                        namespace=namespace,
                        resource_kind="PersistentVolumeClaim",
                        resource_name=name,
                        suffix="unused-pvc",
                        severity="low",
                        issue="PVC does not appear to be mounted by current Pods.",
                        reason=[
                            "The PVC was not found in current Pod volume references.",
                            "Unused PVCs can retain data unnecessarily.",
                        ],
                        recommendation="Delete unused PVCs after confirming the data is no longer needed.",
                    )
                )

        return findings

    def collect_used_pvcs(self, namespace: str) -> Set[str]:
        used = set()

        try:
            pods = self.core_api.list_namespaced_pod(namespace=namespace).items
        except Exception:
            return used

        for pod in pods:
            for volume in pod.spec.volumes or []:
                pvc = volume.persistent_volume_claim
                if pvc and pvc.claim_name:
                    used.add(pvc.claim_name)

        return used

    def finding(
        self,
        namespace: str,
        resource_kind: str,
        resource_name: str,
        suffix: str,
        severity: str,
        issue: str,
        reason: List[str],
        recommendation: str,
    ) -> SecurityFindingModel:
        return SecurityFindingModel(
            name=to_k8s_name(f"{namespace}-{resource_name}-{suffix}"),
            namespace=namespace,
            severity=severity,
            category="storage-security",
            resource_kind=resource_kind,
            resource_name=resource_name,
            issue=issue,
            reason=reason,
            recommendation=recommendation,
            remediation_type="documentation",
            remediation_patch={},
            remediation_command="",
        )