from typing import List

from kubernetes import client

from app.models import SecurityFindingModel
from app.scanners.pod_scanner import PodScanner


class WorkloadScanner:
    """
    Scans workload controller Pod templates.

    Template issues are reported at controller level instead of per Pod.
    """

    def __init__(self, core_api, apps_api, batch_api, profile: dict, logger):
        self.core_api = core_api
        self.apps_api = apps_api
        self.batch_api = batch_api
        self.profile = profile or {}
        self.rules = self.profile.get("rules", {})
        self.logger = logger
        self.pod_scanner = PodScanner(core_api, profile, logger)

    def scan_namespace(self, namespace: str) -> List[SecurityFindingModel]:
        findings: List[SecurityFindingModel] = []
        findings.extend(self.scan_deployments(namespace))
        findings.extend(self.scan_daemonsets(namespace))
        findings.extend(self.scan_statefulsets(namespace))
        findings.extend(self.scan_replicasets(namespace))
        findings.extend(self.scan_jobs(namespace))
        findings.extend(self.scan_cronjobs(namespace))
        return findings

    def scan_deployments(self, namespace: str) -> List[SecurityFindingModel]:
        try:
            items = self.apps_api.list_namespaced_deployment(namespace=namespace).items
        except client.exceptions.ApiException as exc:
            self.logger.warning(f"Could not list Deployments in {namespace}: {exc}")
            return []

        findings = []
        for item in items:
            findings.extend(self.scan_workload_template(
                namespace,
                "Deployment",
                item.metadata.name,
                item.spec.template.spec,
                "deployment-security",
            ))
        return findings

    def scan_daemonsets(self, namespace: str) -> List[SecurityFindingModel]:
        try:
            items = self.apps_api.list_namespaced_daemon_set(namespace=namespace).items
        except client.exceptions.ApiException as exc:
            self.logger.warning(f"Could not list DaemonSets in {namespace}: {exc}")
            return []

        findings = []
        for item in items:
            findings.extend(self.scan_workload_template(
                namespace,
                "DaemonSet",
                item.metadata.name,
                item.spec.template.spec,
                "daemonset-security",
            ))
        return findings

    def scan_statefulsets(self, namespace: str) -> List[SecurityFindingModel]:
        try:
            items = self.apps_api.list_namespaced_stateful_set(namespace=namespace).items
        except client.exceptions.ApiException as exc:
            self.logger.warning(f"Could not list StatefulSets in {namespace}: {exc}")
            return []

        findings = []
        for item in items:
            findings.extend(self.scan_workload_template(
                namespace,
                "StatefulSet",
                item.metadata.name,
                item.spec.template.spec,
                "statefulset-security",
            ))
        return findings

    def scan_replicasets(self, namespace: str) -> List[SecurityFindingModel]:
        try:
            items = self.apps_api.list_namespaced_replica_set(namespace=namespace).items
        except client.exceptions.ApiException as exc:
            self.logger.warning(f"Could not list ReplicaSets in {namespace}: {exc}")
            return []

        findings = []
        for item in items:
            if self.has_owner_kind(item, {"Deployment"}):
                continue

            findings.extend(self.scan_workload_template(
                namespace,
                "ReplicaSet",
                item.metadata.name,
                item.spec.template.spec,
                "replicaset-security",
            ))
        return findings

    def scan_jobs(self, namespace: str) -> List[SecurityFindingModel]:
        try:
            items = self.batch_api.list_namespaced_job(namespace=namespace).items
        except client.exceptions.ApiException as exc:
            self.logger.warning(f"Could not list Jobs in {namespace}: {exc}")
            return []

        findings = []
        for item in items:
            if self.has_owner_kind(item, {"CronJob"}):
                continue

            findings.extend(self.scan_workload_template(
                namespace,
                "Job",
                item.metadata.name,
                item.spec.template.spec,
                "job-security",
            ))
        return findings

    def scan_cronjobs(self, namespace: str) -> List[SecurityFindingModel]:
        try:
            items = self.batch_api.list_namespaced_cron_job(namespace=namespace).items
        except client.exceptions.ApiException as exc:
            self.logger.warning(f"Could not list CronJobs in {namespace}: {exc}")
            return []

        findings = []
        for item in items:
            findings.extend(self.scan_workload_template(
                namespace,
                "CronJob",
                item.metadata.name,
                item.spec.job_template.spec.template.spec,
                "cronjob-security",
            ))
        return findings

    def scan_workload_template(
        self,
        namespace: str,
        workload_kind: str,
        workload_name: str,
        pod_spec,
        category: str,
    ) -> List[SecurityFindingModel]:
        pod_like = type("PodLike", (), {})()
        pod_like.metadata = type("Metadata", (), {})()
        pod_like.metadata.namespace = namespace
        pod_like.metadata.name = f"{workload_kind.lower()}-{workload_name}-template"
        pod_like.metadata.owner_references = []
        pod_like.spec = pod_spec

        findings = self.pod_scanner.scan_pod(pod_like)

        for finding in findings:
            finding.resource_kind = workload_kind
            finding.resource_name = workload_name
            finding.category = category

            finding.name = finding.name.replace(
                f"{workload_kind.lower()}-{workload_name}-template",
                workload_name,
            )

            finding.issue = f"{workload_kind} template: {finding.issue}"
            finding.reason = [f"spec.template: {reason}" for reason in finding.reason]
            finding.remediation_patch = self.rewrite_patch_for_template(finding.remediation_patch)

        return findings

    def rewrite_patch_for_template(self, patch):
        if not patch:
            return None

        pod_spec_patch = patch.get("spec", patch)

        return {
            "spec": {
                "template": {
                    "spec": pod_spec_patch
                }
            }
        }

    def has_owner_kind(self, obj, owner_kinds: set) -> bool:
        owners = obj.metadata.owner_references or []
        return any(owner.kind in owner_kinds for owner in owners)
