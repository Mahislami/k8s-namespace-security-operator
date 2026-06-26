from datetime import datetime, timezone
from typing import List, Set, Dict
import re

from kubernetes import client

from app.models import SecurityFindingModel
from app.scoring import calculate_namespace_score, classify_posture, count_by_severity
from app.scanners.exposure_scanner import ExposureScanner
from app.scanners.namespace_scanner import NamespaceScanner
from app.scanners.network_scanner import NetworkScanner
from app.scanners.pod_scanner import PodScanner
from app.scanners.rbac_scanner import RBACScanner
from app.scanners.workload_scanner import WorkloadScanner
from app.utils import to_k8s_name


class SecurityManager:
    GROUP = "security.meslami.io"
    VERSION = "v1alpha1"

    def __init__(self, logger):
        self.logger = logger
        self.core_api = client.CoreV1Api()
        self.apps_api = client.AppsV1Api()
        self.batch_api = client.BatchV1Api()
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

    def reconcile_namespace(self, namespace: str, profile_name: str = "default-profile"):
        profile = self.load_profile(namespace, profile_name)

        findings: List[SecurityFindingModel] = []

        findings.extend(NamespaceScanner(self.core_api, profile, self.logger).scan_namespace(namespace))

        findings.extend(
            WorkloadScanner(
                self.core_api,
                self.apps_api,
                self.batch_api,
                profile,
                self.logger,
            ).scan_namespace(namespace)
        )

        findings.extend(PodScanner(self.core_api, profile, self.logger).scan_namespace(namespace))

        findings.extend(
            NetworkScanner(
                self.networking_api,
                self.custom_api,
                profile,
                self.logger,
            ).scan_namespace(namespace)
        )

        findings.extend(
            ExposureScanner(
                self.core_api,
                self.networking_api,
                self.custom_api,
                profile,
                self.logger,
            ).scan_namespace(namespace)
        )

        findings.extend(RBACScanner(self.rbac_api, profile, self.logger).scan_namespace(namespace))

        active_findings = self.collapse_findings_for_storage(findings)
        active_finding_names = self.persist_findings_and_remediations(namespace, active_findings)

        self.resolve_stale_findings(namespace, active_finding_names)
        self.update_namespace_report_from_findings(namespace, active_findings, event_mode=False)

    def collapse_findings_for_storage(
        self,
        findings: List[SecurityFindingModel],
    ) -> List[SecurityFindingModel]:
        collapsed: Dict[str, SecurityFindingModel] = {}

        for finding in findings:
            if finding.severity not in ["critical", "high", "medium"]:
                continue

            finding.name = to_k8s_name(finding.name)
            key = finding.name

            if key not in collapsed:
                collapsed[key] = finding
                continue

            existing = collapsed[key]

            for reason in finding.reason:
                if reason not in existing.reason:
                    existing.reason.append(reason)

        return list(collapsed.values())

    def persist_findings_and_remediations(
        self,
        namespace: str,
        findings: List[SecurityFindingModel],
    ) -> Set[str]:
        active_finding_names = set()

        for finding in findings:
            finding_name = to_k8s_name(finding.name)
            remediation_name = to_k8s_name(f"{finding.name}-remediation")

            active_finding_names.add(finding_name)

            self.upsert_security_remediation(
                namespace=namespace,
                remediation_name=remediation_name,
                finding_name=finding_name,
                finding=finding,
            )

            self.upsert_security_finding(
                namespace=namespace,
                finding_name=finding_name,
                remediation_name=remediation_name,
                finding=finding,
            )

        return active_finding_names

    def resolve_stale_findings(self, namespace: str, active_finding_names: Set[str]):
        now = datetime.now(timezone.utc).isoformat()

        try:
            existing = self.custom_api.list_namespaced_custom_object(
                group=self.GROUP,
                version=self.VERSION,
                namespace=namespace,
                plural="securityfindings",
            )
        except client.exceptions.ApiException as exc:
            if exc.status == 404:
                return
            raise

        for item in existing.get("items", []):
            name = item.get("metadata", {}).get("name")
            status = item.get("status", {})
            state = status.get("state")

            if not name:
                continue

            if name in active_finding_names:
                continue

            if state == "Resolved":
                continue

            self.custom_api.patch_namespaced_custom_object_status(
                group=self.GROUP,
                version=self.VERSION,
                namespace=namespace,
                plural="securityfindings",
                name=name,
                body={
                    "status": {
                        "state": "Resolved",
                        "lastSeen": status.get("lastSeen", now),
                        "resolvedAt": now,
                    }
                },
            )

            self.logger.info(f"Marked stale SecurityFinding as Resolved: {namespace}/{name}")

    def normalize_generated_resource_name(self, name: str) -> str:
        if not name:
            return ""
        return re.sub(r"-\d{8,}$", "", name)

    def normalize_issue(self, issue: str) -> str:
        if not issue:
            return ""
        return re.sub(r"Container '.*?' ", "Container ", issue)

    def deduplicate_findings_for_scoring(
        self,
        findings: List[SecurityFindingModel],
    ) -> List[SecurityFindingModel]:
        seen = set()
        unique = []

        for finding in findings:
            normalized_resource = self.normalize_generated_resource_name(finding.resource_name)
            normalized_issue = self.normalize_issue(finding.issue)

            key = (
                finding.severity,
                finding.category,
                finding.resource_kind,
                normalized_resource,
                normalized_issue,
                finding.recommendation,
            )

            if key in seen:
                continue

            seen.add(key)
            unique.append(finding)

        return unique

    def group_findings(self, findings: List[SecurityFindingModel]) -> List[dict]:
        grouped = {}

        for finding in findings:
            normalized_resource = self.normalize_generated_resource_name(finding.resource_name)
            normalized_issue = self.normalize_issue(finding.issue)

            key = (
                finding.severity,
                finding.category,
                finding.resource_kind,
                normalized_resource,
                normalized_issue,
                finding.recommendation,
            )

            if key not in grouped:
                grouped[key] = {
                    "severity": finding.severity,
                    "category": finding.category,
                    "resourceKind": finding.resource_kind,
                    "resourceGroup": normalized_resource,
                    "issue": normalized_issue,
                    "count": 0,
                    "affectedResources": [],
                }

            grouped[key]["count"] += 1

            resource = f"{finding.resource_kind}/{finding.resource_name}"
            if resource not in grouped[key]["affectedResources"]:
                grouped[key]["affectedResources"].append(resource)

        result = list(grouped.values())

        result.sort(
            key=lambda item: (
                self.severity_rank(item["severity"]),
                item["count"],
            ),
            reverse=True,
        )

        for item in result:
            item["affectedResources"] = item["affectedResources"][:10]

        return result[:10]

    def update_namespace_report_from_findings(
        self,
        namespace: str,
        findings: List[SecurityFindingModel],
        event_mode: bool,
    ):
        score_findings = self.deduplicate_findings_for_scoring(findings)
        grouped_findings = self.group_findings(findings)

        score = calculate_namespace_score(score_findings)
        posture = classify_posture(score)
        severity_counts = count_by_severity(findings)

        top_recommendations = [
            f"{f.issue}: {f.recommendation}"
            for f in sorted(
                score_findings,
                key=lambda x: self.severity_rank(x.severity),
                reverse=True,
            )[:5]
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
                "uniqueFindingsForScore": len(score_findings),
                "findingsBySeverity": severity_counts,
                "groupedFindings": grouped_findings,
                "topRecommendations": top_recommendations,
                "lastUpdated": now,
                "monitoringModel": (
                    "Events mark namespaces dirty. A worker coalesces bursts of events "
                    "and reconciles each dirty namespace once. The report is generated "
                    "from the current Active findings produced by a complete namespace scan."
                ),
                "scalabilityNote": (
                    "Short-lived generated Pods are visible but normalized before storage "
                    "and scoring. Repeated timestamped runs are grouped into stable risk "
                    "patterns. Findings that disappear from the latest scan are marked "
                    "Resolved and are not included in the NamespaceSecurityReport score."
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

        spec = {
            "severity": finding.severity,
            "category": finding.category,
            "resourceKind": finding.resource_kind,
            "resourceName": finding.resource_name,
            "issue": finding.issue,
            "reason": finding.reason,
            "recommendation": finding.recommendation,
            "remediationRef": remediation_name,
        }

        metadata = {
            "name": finding_name,
            "namespace": namespace,
            "labels": {
                "security.meslami.io/severity": finding.severity,
                "security.meslami.io/category": finding.category,
            },
        }

        body = {
            "apiVersion": f"{self.GROUP}/{self.VERSION}",
            "kind": "SecurityFinding",
            "metadata": metadata,
            "spec": spec,
        }

        status_body = {
            "status": {
                "state": "Active",
                "lastSeen": now,
            }
        }

        try:
            self.custom_api.create_namespaced_custom_object(
                group=self.GROUP,
                version=self.VERSION,
                namespace=namespace,
                plural="securityfindings",
                body=body,
            )

            status_body["status"]["firstSeen"] = now

            self.custom_api.patch_namespaced_custom_object_status(
                group=self.GROUP,
                version=self.VERSION,
                namespace=namespace,
                plural="securityfindings",
                name=finding_name,
                body=status_body,
            )

        except client.exceptions.ApiException as exc:
            if exc.status == 409:
                self.custom_api.patch_namespaced_custom_object(
                    group=self.GROUP,
                    version=self.VERSION,
                    namespace=namespace,
                    plural="securityfindings",
                    name=finding_name,
                    body={
                        "metadata": metadata,
                        "spec": spec,
                    },
                )

                self.custom_api.patch_namespaced_custom_object_status(
                    group=self.GROUP,
                    version=self.VERSION,
                    namespace=namespace,
                    plural="securityfindings",
                    name=finding_name,
                    body=status_body,
                )
            else:
                raise

    def upsert_security_remediation(
        self,
        namespace: str,
        remediation_name: str,
        finding_name: str,
        finding: SecurityFindingModel,
    ):
        body = {
            "apiVersion": f"{self.GROUP}/{self.VERSION}",
            "kind": "SecurityRemediation",
            "metadata": {
                "name": remediation_name,
                "namespace": namespace,
                "labels": {
                    "security.meslami.io/severity": finding.severity,
                    "security.meslami.io/category": finding.category,
                },
                "annotations": {
                    "security.meslami.io/finding": finding_name,
                },
            },
            "spec": {
                "findingRef": finding_name,
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
                        "metadata": {
                            "labels": body["metadata"]["labels"],
                            "annotations": body["metadata"]["annotations"],
                        },
                        "spec": body["spec"],
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
