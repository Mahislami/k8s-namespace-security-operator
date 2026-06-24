from typing import List

from kubernetes import client

from app.models import SecurityFindingModel


class NetworkScanner:
    """
    Scans namespace network isolation.

    It checks both:
      - Kubernetes NetworkPolicy
      - CiliumNetworkPolicy

    This is useful because the provided cluster has Cilium installed.
    """

    def __init__(
        self,
        networking_api: client.NetworkingV1Api,
        custom_api: client.CustomObjectsApi,
        profile: dict,
        logger,
    ):
        self.networking_api = networking_api
        self.custom_api = custom_api
        self.profile = profile or {}
        self.rules = self.profile.get("rules", {})
        self.logger = logger

    def scan_namespace(self, namespace: str) -> List[SecurityFindingModel]:
        findings = []

        if not self.rules.get("requireNetworkPolicy", True):
            return findings

        has_k8s_np = self.has_kubernetes_network_policy(namespace)
        has_cilium_np = self.has_cilium_network_policy(namespace)

        if not has_k8s_np and not has_cilium_np:
            findings.append(SecurityFindingModel(
                name=f"{namespace}-missing-network-policy",
                severity="medium",
                category="network-security",
                namespace=namespace,
                resource_kind="Namespace",
                resource_name=namespace,
                issue="Namespace has no NetworkPolicy or CiliumNetworkPolicy",
                reason=[
                    "No networking.k8s.io/NetworkPolicy found",
                    "No cilium.io/CiliumNetworkPolicy found",
                ],
                recommendation="Create a default-deny NetworkPolicy or CiliumNetworkPolicy and explicitly allow required traffic.",
                remediation_type="network-policy",
                remediation_patch={
                    "apiVersion": "networking.k8s.io/v1",
                    "kind": "NetworkPolicy",
                    "metadata": {
                        "name": "default-deny",
                        "namespace": namespace,
                    },
                    "spec": {
                        "podSelector": {},
                        "policyTypes": ["Ingress", "Egress"],
                    },
                },
            ))

        return findings

    def has_kubernetes_network_policy(self, namespace: str) -> bool:
        try:
            policies = self.networking_api.list_namespaced_network_policy(namespace=namespace).items
            return len(policies) > 0
        except client.exceptions.ApiException as exc:
            self.logger.warning(f"Could not list NetworkPolicies in {namespace}: {exc}")
            return False

    def has_cilium_network_policy(self, namespace: str) -> bool:
        try:
            result = self.custom_api.list_namespaced_custom_object(
                group="cilium.io",
                version="v2",
                namespace=namespace,
                plural="ciliumnetworkpolicies",
            )
            return len(result.get("items", [])) > 0
        except client.exceptions.ApiException as exc:
            self.logger.debug(f"Could not list CiliumNetworkPolicies in {namespace}: {exc}")
            return False
