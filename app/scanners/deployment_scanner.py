from typing import List

from app.models import SecurityFindingModel
from app.scanners.pod_scanner import PodScanner


class DeploymentScanner:
    """
    Scans Deployment security without listing Pods.

    It checks:
    - Deployment-level resilience/security settings
    - Deployment.spec.template security by reusing PodScanner
    """

    def __init__(self, core_api, profile: dict, logger):
        self.profile = profile or {}
        self.rules = self.profile.get("rules", {})
        self.logger = logger
        self.pod_scanner = PodScanner(core_api, profile, logger)

    def scan_deployment(self, deployment) -> List[SecurityFindingModel]:
        findings: List[SecurityFindingModel] = []

        namespace = deployment.metadata.namespace
        deployment_name = deployment.metadata.name

        findings.extend(self.scan_deployment_level_rules(deployment))

        # Build a lightweight Pod-like object from Deployment.spec.template.
        pod_like = type("PodLike", (), {})()
        pod_like.metadata = type("Metadata", (), {})()
        pod_like.metadata.namespace = namespace
        pod_like.metadata.name = f"deployment-{deployment_name}-template"
        pod_like.spec = deployment.spec.template.spec

        template_findings = self.pod_scanner.scan_pod(pod_like)

        for finding in template_findings:
            finding.resource_kind = "Deployment"
            finding.resource_name = deployment_name
            finding.name = finding.name.replace(
                f"deployment-{deployment_name}-template",
                deployment_name,
            )

        findings.extend(template_findings)
        return findings

    def scan_deployment_level_rules(self, deployment) -> List[SecurityFindingModel]:
        findings: List[SecurityFindingModel] = []

        namespace = deployment.metadata.namespace
        name = deployment.metadata.name
        spec = deployment.spec

        if self.rules.get("requireDeploymentReplicas", True):
            minimum = self.rules.get("minimumDeploymentReplicas", 2)
            replicas = spec.replicas or 1

            if replicas < minimum:
                findings.append(SecurityFindingModel(
                    name=f"{namespace}-{name}-low-replica-count",
                    severity="low",
                    category="deployment-security",
                    namespace=namespace,
                    resource_kind="Deployment",
                    resource_name=name,
                    issue=f"Deployment has fewer than {minimum} replicas",
                    reason=[f"spec.replicas={replicas}"],
                    recommendation=f"Set spec.replicas to at least {minimum} for better availability.",
                    remediation_type="manifest-patch",
                    remediation_patch={"spec": {"replicas": minimum}},
                ))

        if self.rules.get("requireRollingUpdateStrategy", True):
            strategy = spec.strategy.type if spec.strategy else None

            if strategy != "RollingUpdate":
                findings.append(SecurityFindingModel(
                    name=f"{namespace}-{name}-non-rolling-update-strategy",
                    severity="low",
                    category="deployment-security",
                    namespace=namespace,
                    resource_kind="Deployment",
                    resource_name=name,
                    issue="Deployment does not use RollingUpdate strategy",
                    reason=[f"spec.strategy.type={strategy}"],
                    recommendation="Use RollingUpdate strategy to reduce disruption during updates.",
                    remediation_type="manifest-patch",
                    remediation_patch={"spec": {"strategy": {"type": "RollingUpdate"}}},
                ))

        return findings
