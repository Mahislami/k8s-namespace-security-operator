from datetime import datetime, timezone
from typing import List

from kubernetes import client

from app.models import SecurityFindingModel
from app.scoring import calculate_namespace_score, classify_posture, count_by_severity
from app.scanners.deployment_scanner import DeploymentScanner
from app.scanners.exposure_scanner import ExposureScanner
from app.scanners.namespace_scanner import NamespaceScanner
from app.scanners.network_scanner import NetworkScanner
from app.scanners.pod_scanner import PodScanner
from app.scanners.rbac_scanner import RBACScanner
from app.utils import to_k8s_name


class SecurityManager:
    """
    Orchestrates namespace security evaluation.

    The operator monitors namespace posture by watching security-relevant
    resources inside each namespace.

    Normal scalable path:
      - Pod event        -> scan only that Pod
      - Deployment event -> scan only Deployment.spec.template

    Consistency path:
      - Namespace, RBAC, NetworkPolicy, Service and periodic events reconcile
        the namespace using paginated scans.
    """

    GROUP = "security.meslami.io"
    VERSION = "v1alpha1"

    def __init__(self, logger):
        self.logger = logger
        self.core_api = client.CoreV1Api()
        self.rbac_api = client.RbacAuthorizationV1Api()
        self.networking_api = client.NetworkingV1Api()
        self.custom_api = client.CustomObjectsApi()

    def load_profile(self, namespace: str, profile_name: str = "default-profile") -> dict:
        try:
            obj = self.custom_api.get_namespaced_custom_object(
                group=self.GROUP,
                version=self.VERSION,
                namespace=namespace,
                plural="securitypolicyprofiles",
                name=profile_name,
            )
            return obj.get("spec", {})
        except client.exceptions.ApiException as exc:
            if exc.status == 404:
                self.logger.warning(
                    f"SecurityPolicyProfile '{profile_name}' not found in {namespace}; using built-in defaults."
                )
                return {}
            raise

    def handle_pod_event(self, pod_body: dict, namespace: str):
        profile = self.load_profile(namespace)

        pod_name = pod_body.get("metadata", {}).get("name")
        if not pod_name:
            self.logger.warning("Pod event body has no metadata.name; skipping.")
            return

        pod = self.core_api.read_namespaced_pod(
            name=pod_name,
            namespace=namespace,
        )

        scanner = PodScanner(self.core_api, profile, self.logger)
        findings = scanner.scan_pod(pod)

        self.persist_findings_and_remediations(namespace, findings)
        self.update_namespace_report_from_findings(namespace, findings, event_mode=True)

    def handle_pod_delete(self, namespace: str):
        self.reconcile_namespace(namespace)

    def handle_deployment_event(self, deployment_body: dict, namespace: str):
        profile = self.load_profile(namespace)

        deployment_name = deployment_body.get("metadata", {}).get("name")
        if not deployment_name:
            self.logger.warning("Deployment event body has no metadata.name; skipping.")
            return

        apps_api = client.AppsV1Api()
        deployment = apps_api.read_namespaced_deployment(
            name=deployment_name,
            namespace=namespace,
        )

        scanner = DeploymentScanner(self.core_api, profile, self.logger)
        findings = scanner.scan_deployment(deployment)

        self.persist_findings_and_remediations(namespace, findings)
        self.update_namespace_report_from_findings(namespace, findings, event_mode=True)

    def reconcile_namespace(self, namespace: str, profile_name: str = "default-profile"):
        profile = self.load_profile(namespace, profile_name)

        namespace_scanner = NamespaceScanner(self.core_api, profile, self.logger)
        pod_scanner = PodScanner(self.core_api, profile, self.logger)
        network_scanner = NetworkScanner(self.networking_api, self.custom_api, profile, self.logger)
        exposure_scanner = ExposureScanner(self.core_api, self.networking_api, self.custom_api, profile, self.logger)
        rbac_scanner = RBACScanner(self.rbac_api, profile, self.logger)

        findings: List[SecurityFindingModel] = []
        findings.extend(namespace_scanner.scan_namespace(namespace))
        findings.extend(pod_scanner.scan_namespace(namespace))
        findings.extend(network_scanner.scan_namespace(namespace))
        findings.extend(exposure_scanner.scan_namespace(namespace))
        findings.extend(rbac_scanner.scan_namespace(namespace))

        self.persist_findings_and_remediations(namespace, findings)
        self.update_namespace_report_from_findings(namespace, findings, event_mode=False)

    def persist_findings_and_remediations(self, namespace: str, findings: List[SecurityFindingModel]):
        for finding in findings:
            if finding.severity not in ["critical", "high", "medium"]:
                continue

            finding_name = to_k8s_name(finding.name)
            remediation_name = to_k8s_name(f"{finding.name}-remediation")

            self.upsert_security_remediation(namespace, remediation_name, finding)
            self.upsert_security_finding(namespace, finding_name, remediation_name, finding)

    def update_namespace_report_from_findings(
        self,
        namespace: str,
        findings: List[SecurityFindingModel],
        event_mode: bool,
    ):
        score = calculate_namespace_score(findings)
        posture = classify_posture(score)
        severity_counts = count_by_severity(findings)

        top_recommendations = [
            f"{f.issue}: {f.recommendation}"
            for f in sorted(findings, key=lambda x: self.severity_rank(x.severity), reverse=True)[:5]
        ]

        report_name = to_k8s_name(namespace)
        now = datetime.now(timezone.utc).isoformat()

        body = {
            "apiVersion": f"{self.GROUP}/{self.VERSION}",
            "kind": "NamespaceSecurityReport",
            "metadata": {
                "name": report_name,
                "namespace": namespace,
            },
            "spec": {
                "namespace": namespace,
            },
        }

        status_body = {
            "status": {
                "namespace": namespace,
                "profileUsed": "default-profile",
                "score": score,
                "posture": posture,
                "eventMode": event_mode,
                "totalFindingsEvaluated": len(findings),
                "findingsBySeverity": severity_counts,
                "topRecommendations": top_recommendations,
                "lastUpdated": now,
                "monitoringModel": (
                    "Namespace posture is monitored by watching security-relevant "
                    "resources: Namespace, Pods, Deployments, ServiceAccounts, "
                    "RoleBindings, Services, Ingresses, NetworkPolicies, "
                    "CiliumNetworkPolicies, and Traefik IngressRoutes."
                ),
                "scalabilityNote": (
                    "Pod events scan only the changed Pod. Deployment events scan only "
                    "spec.template. Full namespace reconciliation is paginated and used "
                    "for consistency."
                ),
            }
        }

        try:
            self.custom_api.create_namespaced_custom_object(
                group=self.GROUP,
                version=self.VERSION,
                namespace=namespace,
                plural="namespacesecurityreports",
                body=body,
            )
            self.logger.info(f"Created NamespaceSecurityReport for {namespace}")
        except client.exceptions.ApiException as exc:
            if exc.status == 409:
                self.custom_api.patch_namespaced_custom_object(
                    group=self.GROUP,
                    version=self.VERSION,
                    namespace=namespace,
                    plural="namespacesecurityreports",
                    name=report_name,
                    body=body,
                )
                self.logger.info(f"Patched NamespaceSecurityReport spec for {namespace}")
            else:
                raise

        self.custom_api.patch_namespaced_custom_object_status(
            group=self.GROUP,
            version=self.VERSION,
            namespace=namespace,
            plural="namespacesecurityreports",
            name=report_name,
            body=status_body,
        )
        self.logger.info(f"Updated NamespaceSecurityReport status for {namespace}")

    def upsert_security_finding(
        self,
        namespace: str,
        finding_name: str,
        remediation_name: str,
        finding: SecurityFindingModel,
    ):
        now = datetime.now(timezone.utc).isoformat()

        body = {
            "apiVersion": f"{self.GROUP}/{self.VERSION}",
            "kind": "SecurityFinding",
            "metadata": {
                "name": finding_name,
                "namespace": namespace,
                "labels": {
                    "security.meslami.io/severity": finding.severity,
                    "security.meslami.io/category": finding.category,
                },
            },
            "spec": {
                "severity": finding.severity,
                "category": finding.category,
                "resourceKind": finding.resource_kind,
                "resourceName": finding.resource_name,
                "issue": finding.issue,
                "reason": finding.reason,
                "recommendation": finding.recommendation,
                "remediationRef": remediation_name,
            },
            "status": {
                "state": "Active",
                "firstSeen": now,
                "lastSeen": now,
            },
        }

        try:
            self.custom_api.create_namespaced_custom_object(
                group=self.GROUP,
                version=self.VERSION,
                namespace=namespace,
                plural="securityfindings",
                body=body,
            )
        except client.exceptions.ApiException as exc:
            if exc.status == 409:
                self.custom_api.patch_namespaced_custom_object_status(
                    group=self.GROUP,
                    version=self.VERSION,
                    namespace=namespace,
                    plural="securityfindings",
                    name=finding_name,
                    body={
                        "status": {
                            "state": "Active",
                            "lastSeen": now,
                        }
                    },
                )
            else:
                raise

    def upsert_security_remediation(
        self,
        namespace: str,
        remediation_name: str,
        finding: SecurityFindingModel,
    ):
        body = {
            "apiVersion": f"{self.GROUP}/{self.VERSION}",
            "kind": "SecurityRemediation",
            "metadata": {
                "name": remediation_name,
                "namespace": namespace,
            },
            "spec": {
                "findingRef": to_k8s_name(finding.name),
                "mode": "suggest",
                "actionType": finding.remediation_type,
                "description": finding.recommendation,
                "patch": finding.remediation_patch or {},
                "command": finding.remediation_command or "",
                "risk": self.remediation_risk(finding.severity),
            },
        }

        try:
            self.custom_api.create_namespaced_custom_object(
                group=self.GROUP,
                version=self.VERSION,
                namespace=namespace,
                plural="securityremediations",
                body=body,
            )
        except client.exceptions.ApiException as exc:
            if exc.status == 409:
                self.custom_api.patch_namespaced_custom_object(
                    group=self.GROUP,
                    version=self.VERSION,
                    namespace=namespace,
                    plural="securityremediations",
                    name=remediation_name,
                    body={
                        "spec": body["spec"]
                    },
                )
            else:
                raise

    def severity_rank(self, severity: str) -> int:
        return {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }.get(severity, 0)

    def remediation_risk(self, severity: str) -> str:
        if severity in ["critical", "high"]:
            return "medium"
        return "low"
