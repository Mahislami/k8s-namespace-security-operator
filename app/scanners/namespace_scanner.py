from typing import List

from kubernetes import client

from app.models import SecurityFindingModel


class NamespaceScanner:
    """
    Scans the Namespace object itself.

    This scanner checks namespace-level security configuration, such as
    Pod Security Admission labels.

    SecurityManager is still the orchestrator. NamespaceScanner only checks
    namespace metadata and namespace-level settings.
    """

    def __init__(self, core_api: client.CoreV1Api, profile: dict, logger):
        self.core_api = core_api
        self.profile = profile or {}
        self.rules = self.profile.get("rules", {})
        self.logger = logger

    def scan_namespace(self, namespace: str) -> List[SecurityFindingModel]:
        findings: List[SecurityFindingModel] = []

        try:
            ns_obj = self.core_api.read_namespace(name=namespace)
        except client.exceptions.ApiException as exc:
            self.logger.warning(f"Could not read namespace {namespace}: {exc}")
            return findings

        labels = ns_obj.metadata.labels or {}

        if self.rules.get("requirePodSecurityRestricted", True):
            enforce = labels.get("pod-security.kubernetes.io/enforce")

            if enforce != "restricted":
                findings.append(SecurityFindingModel(
                    name=f"{namespace}-pod-security-admission-not-restricted",
                    severity="medium",
                    category="namespace-security",
                    namespace=namespace,
                    resource_kind="Namespace",
                    resource_name=namespace,
                    issue="Namespace does not enforce Pod Security Admission restricted profile",
                    reason=[f"pod-security.kubernetes.io/enforce={enforce}"],
                    recommendation="Label the namespace with pod-security.kubernetes.io/enforce=restricted.",
                    remediation_type="command",
                    remediation_command=(
                        f"kubectl label namespace {namespace} "
                        "pod-security.kubernetes.io/enforce=restricted --overwrite"
                    ),
                ))

        return findings
