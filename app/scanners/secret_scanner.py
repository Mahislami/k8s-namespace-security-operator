from typing import List, Set

from app.models import SecurityFindingModel
from app.utils import to_k8s_name


class SecretScanner:
    """
    Secret metadata scanner.

    It never exposes Secret values. It checks only metadata, type, key names,
    and usage references.
    """

    SUSPICIOUS_KEYWORDS = [
        "password",
        "passwd",
        "pwd",
        "token",
        "secret",
        "apikey",
        "api_key",
        "access_key",
        "private",
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
            secrets = self.core_api.list_namespaced_secret(namespace=namespace).items
        except Exception as exc:
            self.logger.warning(f"Failed to list Secrets in {namespace}: {exc}")
            return findings

        used_secrets = self.collect_used_secrets(namespace)

        for secret in secrets:
            name = secret.metadata.name
            secret_type = secret.type or ""
            data_keys = list((secret.data or {}).keys())

            if secret_type == "kubernetes.io/service-account-token":
                findings.append(
                    self.finding(
                        namespace=namespace,
                        secret_name=name,
                        suffix="service-account-token-secret",
                        severity="medium",
                        issue="Legacy ServiceAccount token Secret exists.",
                        reason=[
                            "Long-lived ServiceAccount token Secrets increase credential exposure risk.",
                            "Prefer projected ServiceAccount tokens where possible.",
                        ],
                        recommendation="Avoid long-lived ServiceAccount token Secrets unless explicitly required.",
                    )
                )

            if name not in used_secrets and not self.is_system_generated_secret(name):
                findings.append(
                    self.finding(
                        namespace=namespace,
                        secret_name=name,
                        suffix="unused-secret",
                        severity="low",
                        issue="Secret does not appear to be referenced by current Pods.",
                        reason=[
                            "The Secret was not found in Pod volume mounts, envFrom, secretKeyRef, or imagePullSecrets.",
                            "Unused Secrets increase credential sprawl.",
                        ],
                        recommendation="Remove unused Secrets or verify whether external controllers still require them.",
                    )
                )

            suspicious_keys = [
                key
                for key in data_keys
                if any(keyword in key.lower() for keyword in self.SUSPICIOUS_KEYWORDS)
            ]

            if suspicious_keys:
                findings.append(
                    self.finding(
                        namespace=namespace,
                        secret_name=name,
                        suffix="suspicious-secret-key-names",
                        severity="low",
                        issue="Secret contains sensitive-looking key names.",
                        reason=[
                            "Secret keys suggest credentials are stored in this object.",
                            "The scanner does not read or expose Secret values.",
                        ],
                        recommendation="Ensure Secret access is tightly scoped and only mounted where required.",
                    )
                )

        return findings

    def collect_used_secrets(self, namespace: str) -> Set[str]:
        used = set()

        try:
            pods = self.core_api.list_namespaced_pod(namespace=namespace).items
        except Exception:
            return used

        for pod in pods:
            spec = pod.spec

            for volume in spec.volumes or []:
                if volume.secret and volume.secret.secret_name:
                    used.add(volume.secret.secret_name)

            for container in list(spec.containers or []) + list(spec.init_containers or []):
                for env_from in container.env_from or []:
                    if env_from.secret_ref and env_from.secret_ref.name:
                        used.add(env_from.secret_ref.name)

                for env in container.env or []:
                    if env.value_from and env.value_from.secret_key_ref:
                        used.add(env.value_from.secret_key_ref.name)

            for pull_secret in spec.image_pull_secrets or []:
                if pull_secret.name:
                    used.add(pull_secret.name)

        return used

    def is_system_generated_secret(self, name: str) -> bool:
        lowered = name.lower()
        return (
            name.startswith("default-token-")
            or name.endswith("-token")
            or "docker" in lowered
            or "registry" in lowered
            or "pull" in lowered
        )

    def finding(
        self,
        namespace: str,
        secret_name: str,
        suffix: str,
        severity: str,
        issue: str,
        reason: List[str],
        recommendation: str,
    ) -> SecurityFindingModel:
        return SecurityFindingModel(
            name=to_k8s_name(f"{namespace}-{secret_name}-{suffix}"),
            namespace=namespace,
            severity=severity,
            category="secret-security",
            resource_kind="Secret",
            resource_name=secret_name,
            issue=issue,
            reason=reason,
            recommendation=recommendation,
            remediation_type="documentation",
            remediation_patch={},
            remediation_command="",
        )