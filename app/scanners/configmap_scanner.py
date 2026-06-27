from typing import List

from app.models import SecurityFindingModel
from app.utils import to_k8s_name


class ConfigMapScanner:
    """
    ConfigMap scanner.

    It avoids exposing ConfigMap values and checks key names only.
    """

    SENSITIVE_KEYWORDS = [
        "password",
        "passwd",
        "pwd",
        "token",
        "secret",
        "apikey",
        "api_key",
        "access_key",
        "private_key",
        "credential",
    ]

    def __init__(self, core_api, profile: dict, logger):
        self.core_api = core_api
        self.profile = profile or {}
        self.rules = self.profile.get("rules", {})
        self.logger = logger

    def scan_namespace(self, namespace: str) -> List[SecurityFindingModel]:
        findings = []

        try:
            configmaps = self.core_api.list_namespaced_config_map(
                namespace=namespace
            ).items
        except Exception as exc:
            self.logger.warning(f"Failed to list ConfigMaps in {namespace}: {exc}")
            return findings

        for configmap in configmaps:
            name = configmap.metadata.name
            keys = list((configmap.data or {}).keys())

            suspicious_keys = [
                key
                for key in keys
                if any(keyword in key.lower() for keyword in self.SENSITIVE_KEYWORDS)
            ]

            if suspicious_keys:
                findings.append(
                    self.finding(
                        namespace=namespace,
                        configmap_name=name,
                        suffix="sensitive-looking-configmap-keys",
                        severity="medium",
                        issue="ConfigMap contains sensitive-looking key names.",
                        reason=[
                            "ConfigMaps are not designed for secret material.",
                            "Sensitive-looking keys were found, but values were not inspected or exposed.",
                        ],
                        recommendation="Move secrets or credentials from ConfigMaps into Kubernetes Secrets or an external secret manager.",
                    )
                )

        return findings

    def finding(
        self,
        namespace: str,
        configmap_name: str,
        suffix: str,
        severity: str,
        issue: str,
        reason: List[str],
        recommendation: str,
    ) -> SecurityFindingModel:
        return SecurityFindingModel(
            name=to_k8s_name(f"{namespace}-{configmap_name}-{suffix}"),
            namespace=namespace,
            severity=severity,
            category="configmap-security",
            resource_kind="ConfigMap",
            resource_name=configmap_name,
            issue=issue,
            reason=reason,
            recommendation=recommendation,
            remediation_type="documentation",
            remediation_patch={},
            remediation_command="",
        )