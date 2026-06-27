from typing import Iterable, List

from app.models import SecurityFindingModel
from app.utils import to_k8s_name


class ImageScanner:
    """
    Lightweight image policy scanner.

    This is not CVE scanning. It checks image hygiene:
    - latest tag
    - missing tag
    - not pinned by digest
    - untrusted registry if trustedRegistries is configured
    """

    def __init__(self, core_api, apps_api, batch_api, profile: dict, logger):
        self.core_api = core_api
        self.apps_api = apps_api
        self.batch_api = batch_api
        self.profile = profile or {}
        self.rules = self.profile.get("rules", {})
        self.logger = logger
        self.trusted_registries = self.rules.get("trustedRegistries", [])

    def scan_namespace(self, namespace: str) -> List[SecurityFindingModel]:
        findings = []

        findings.extend(self.scan_pods(namespace))
        findings.extend(self.scan_deployments(namespace))
        findings.extend(self.scan_daemonsets(namespace))
        findings.extend(self.scan_statefulsets(namespace))
        findings.extend(self.scan_jobs(namespace))
        findings.extend(self.scan_cronjobs(namespace))

        return findings

    def scan_pods(self, namespace: str) -> List[SecurityFindingModel]:
        findings = []

        try:
            pods = self.core_api.list_namespaced_pod(namespace=namespace).items
        except Exception as exc:
            self.logger.warning(
                f"Failed to list Pods for image scanning in {namespace}: {exc}"
            )
            return findings

        for pod in pods:
            if pod.metadata.owner_references:
                continue

            findings.extend(
                self.scan_pod_spec_images(
                    namespace=namespace,
                    resource_kind="Pod",
                    resource_name=pod.metadata.name,
                    pod_spec=pod.spec,
                )
            )

        return findings

    def scan_deployments(self, namespace: str) -> List[SecurityFindingModel]:
        findings = []

        try:
            deployments = self.apps_api.list_namespaced_deployment(
                namespace=namespace
            ).items
        except Exception as exc:
            self.logger.warning(
                f"Failed to list Deployments for image scanning in {namespace}: {exc}"
            )
            return findings

        for deployment in deployments:
            findings.extend(
                self.scan_pod_spec_images(
                    namespace=namespace,
                    resource_kind="Deployment",
                    resource_name=deployment.metadata.name,
                    pod_spec=deployment.spec.template.spec,
                )
            )

        return findings

    def scan_daemonsets(self, namespace: str) -> List[SecurityFindingModel]:
        findings = []

        try:
            daemonsets = self.apps_api.list_namespaced_daemon_set(
                namespace=namespace
            ).items
        except Exception as exc:
            self.logger.warning(
                f"Failed to list DaemonSets for image scanning in {namespace}: {exc}"
            )
            return findings

        for daemonset in daemonsets:
            findings.extend(
                self.scan_pod_spec_images(
                    namespace=namespace,
                    resource_kind="DaemonSet",
                    resource_name=daemonset.metadata.name,
                    pod_spec=daemonset.spec.template.spec,
                )
            )

        return findings

    def scan_statefulsets(self, namespace: str) -> List[SecurityFindingModel]:
        findings = []

        try:
            statefulsets = self.apps_api.list_namespaced_stateful_set(
                namespace=namespace
            ).items
        except Exception as exc:
            self.logger.warning(
                f"Failed to list StatefulSets for image scanning in {namespace}: {exc}"
            )
            return findings

        for statefulset in statefulsets:
            findings.extend(
                self.scan_pod_spec_images(
                    namespace=namespace,
                    resource_kind="StatefulSet",
                    resource_name=statefulset.metadata.name,
                    pod_spec=statefulset.spec.template.spec,
                )
            )

        return findings

    def scan_jobs(self, namespace: str) -> List[SecurityFindingModel]:
        findings = []

        try:
            jobs = self.batch_api.list_namespaced_job(namespace=namespace).items
        except Exception as exc:
            self.logger.warning(
                f"Failed to list Jobs for image scanning in {namespace}: {exc}"
            )
            return findings

        for job in jobs:
            findings.extend(
                self.scan_pod_spec_images(
                    namespace=namespace,
                    resource_kind="Job",
                    resource_name=job.metadata.name,
                    pod_spec=job.spec.template.spec,
                )
            )

        return findings

    def scan_cronjobs(self, namespace: str) -> List[SecurityFindingModel]:
        findings = []

        try:
            cronjobs = self.batch_api.list_namespaced_cron_job(
                namespace=namespace
            ).items
        except Exception as exc:
            self.logger.warning(
                f"Failed to list CronJobs for image scanning in {namespace}: {exc}"
            )
            return findings

        for cronjob in cronjobs:
            findings.extend(
                self.scan_pod_spec_images(
                    namespace=namespace,
                    resource_kind="CronJob",
                    resource_name=cronjob.metadata.name,
                    pod_spec=cronjob.spec.job_template.spec.template.spec,
                )
            )

        return findings

    def all_containers(self, pod_spec) -> Iterable:
        containers = []
        containers.extend(pod_spec.containers or [])
        containers.extend(pod_spec.init_containers or [])
        return containers

    def scan_pod_spec_images(
        self,
        namespace: str,
        resource_kind: str,
        resource_name: str,
        pod_spec,
    ) -> List[SecurityFindingModel]:
        findings = []

        for container in self.all_containers(pod_spec):
            image = container.image or ""
            container_name = container.name

            if self.image_uses_latest(image):
                findings.append(
                    self.finding(
                        namespace=namespace,
                        resource_kind=resource_kind,
                        resource_name=resource_name,
                        container_name=container_name,
                        suffix="latest-image-tag",
                        severity="medium",
                        issue=f"Container '{container_name}' uses mutable image tag ':latest'.",
                        reason=[
                            f"Image '{image}' is mutable and may change without a manifest update."
                        ],
                        recommendation="Use an immutable version tag or pin the image by digest.",
                    )
                )

            if self.image_has_no_tag(image):
                findings.append(
                    self.finding(
                        namespace=namespace,
                        resource_kind=resource_kind,
                        resource_name=resource_name,
                        container_name=container_name,
                        suffix="missing-image-tag",
                        severity="medium",
                        issue=f"Container '{container_name}' image has no explicit tag.",
                        reason=[f"Image '{image}' does not specify a tag."],
                        recommendation="Use an explicit version tag or digest.",
                    )
                )

            if not self.image_pinned_by_digest(image):
                findings.append(
                    self.finding(
                        namespace=namespace,
                        resource_kind=resource_kind,
                        resource_name=resource_name,
                        container_name=container_name,
                        suffix="image-not-pinned-by-digest",
                        severity="low",
                        issue=f"Container '{container_name}' image is not pinned by digest.",
                        reason=[
                            f"Image '{image}' does not include '@sha256:' digest pinning."
                        ],
                        recommendation="Pin production images by digest for stronger supply-chain integrity.",
                    )
                )

            if self.trusted_registries and not self.image_from_trusted_registry(image):
                findings.append(
                    self.finding(
                        namespace=namespace,
                        resource_kind=resource_kind,
                        resource_name=resource_name,
                        container_name=container_name,
                        suffix="untrusted-image-registry",
                        severity="high",
                        issue=f"Container '{container_name}' uses image from untrusted registry.",
                        reason=[
                            f"Image '{image}' is not from configured trusted registries: {self.trusted_registries}."
                        ],
                        recommendation="Use an approved internal or trusted container registry.",
                    )
                )

        return findings

    def image_uses_latest(self, image: str) -> bool:
        return image.endswith(":latest")

    def image_has_no_tag(self, image: str) -> bool:
        if "@" in image:
            return False
        return ":" not in image.split("/")[-1]

    def image_pinned_by_digest(self, image: str) -> bool:
        return "@sha256:" in image

    def extract_registry(self, image: str) -> str:
        first = image.split("/")[0]
        if "." in first or ":" in first:
            return first
        return "docker.io"

    def image_from_trusted_registry(self, image: str) -> bool:
        registry = self.extract_registry(image)
        return registry in self.trusted_registries

    def finding(
        self,
        namespace: str,
        resource_kind: str,
        resource_name: str,
        container_name: str,
        suffix: str,
        severity: str,
        issue: str,
        reason: List[str],
        recommendation: str,
    ) -> SecurityFindingModel:
        return SecurityFindingModel(
            name=to_k8s_name(f"{namespace}-{resource_name}-{container_name}-{suffix}"),
            namespace=namespace,
            severity=severity,
            category="image-security",
            resource_kind=resource_kind,
            resource_name=resource_name,
            issue=issue,
            reason=reason,
            recommendation=recommendation,
            remediation_type="documentation",
            remediation_patch={},
            remediation_command="",
        )