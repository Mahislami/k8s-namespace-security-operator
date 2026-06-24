from typing import List

from kubernetes import client

from app.models import SecurityFindingModel


class RBACScanner:
    """
    Scans namespace RoleBindings for risky RBAC patterns.

    For this challenge we focus on namespaced RBAC because the task is
    namespace security posture.
    """

    def __init__(self, rbac_api: client.RbacAuthorizationV1Api, profile: dict, logger):
        self.rbac_api = rbac_api
        self.profile = profile or {}
        self.rules = self.profile.get("rules", {})
        self.logger = logger

    def scan_namespace(self, namespace: str) -> List[SecurityFindingModel]:
        findings: List[SecurityFindingModel] = []

        try:
            rolebindings = self.rbac_api.list_namespaced_role_binding(namespace=namespace).items
        except client.exceptions.ApiException as exc:
            self.logger.warning(f"Could not list RoleBindings in {namespace}: {exc}")
            return findings

        for rb in rolebindings:
            role_ref = rb.role_ref
            role_name = role_ref.name if role_ref else ""

            if self.rules.get("forbidClusterAdminRoleBinding", True):
                if role_name == "cluster-admin":
                    findings.append(SecurityFindingModel(
                        name=f"{namespace}-{rb.metadata.name}-cluster-admin-rolebinding",
                        severity="critical",
                        category="rbac",
                        namespace=namespace,
                        resource_kind="RoleBinding",
                        resource_name=rb.metadata.name,
                        issue="RoleBinding grants cluster-admin privileges inside the namespace",
                        reason=[f"roleRef.name={role_name}"],
                        recommendation="Avoid binding cluster-admin. Create a least-privilege Role or ClusterRole instead.",
                        remediation_type="documentation",
                    ))

            subjects = rb.subjects or []
            for subject in subjects:
                if self.rules.get("flagDefaultServiceAccountRBAC", True):
                    if subject.kind == "ServiceAccount" and subject.name == "default":
                        findings.append(SecurityFindingModel(
                            name=f"{namespace}-{rb.metadata.name}-default-serviceaccount-rbac",
                            severity="high",
                            category="rbac",
                            namespace=namespace,
                            resource_kind="RoleBinding",
                            resource_name=rb.metadata.name,
                            issue="RoleBinding grants permissions to the default ServiceAccount",
                            reason=[f"subject=ServiceAccount:{namespace}:default"],
                            recommendation="Create a dedicated ServiceAccount and bind permissions only to that account.",
                            remediation_type="documentation",
                        ))

        return findings
