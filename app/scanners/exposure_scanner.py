from typing import List

from kubernetes import client

from app.models import SecurityFindingModel


SENSITIVE_PORTS = {
    22: "SSH",
    2379: "etcd client",
    2380: "etcd peer",
    6443: "Kubernetes API server",
    10250: "Kubelet API",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
}


class ExposureScanner:
    """
    Scans namespace exposure risks.

    This scanner checks whether workloads are exposed through:
      - LoadBalancer Services
      - NodePort Services
      - Ingress resources without TLS
      - Traefik IngressRoute resources without TLS

    This complements NetworkScanner:
      - NetworkScanner checks internal namespace isolation.
      - ExposureScanner checks external/public exposure.
    """

    def __init__(self, core_api: client.CoreV1Api, networking_api: client.NetworkingV1Api, custom_api: client.CustomObjectsApi, profile: dict, logger):
        self.core_api = core_api
        self.networking_api = networking_api
        self.custom_api = custom_api
        self.profile = profile or {}
        self.rules = self.profile.get("rules", {})
        self.logger = logger

    def scan_namespace(self, namespace: str) -> List[SecurityFindingModel]:
        findings: List[SecurityFindingModel] = []

        findings.extend(self.scan_services(namespace))
        findings.extend(self.scan_ingresses(namespace))
        findings.extend(self.scan_traefik_ingressroutes(namespace))

        return findings

    def scan_services(self, namespace: str) -> List[SecurityFindingModel]:
        findings: List[SecurityFindingModel] = []

        try:
            services = self.core_api.list_namespaced_service(namespace=namespace).items
        except client.exceptions.ApiException as exc:
            self.logger.warning(f"Could not list Services in {namespace}: {exc}")
            return findings

        for service in services:
            service_type = service.spec.type
            service_name = service.metadata.name

            if self.rules.get("flagLoadBalancerServices", True) and service_type == "LoadBalancer":
                findings.append(SecurityFindingModel(
                    name=f"{namespace}-{service_name}-loadbalancer-exposure",
                    severity="high",
                    category="network-security",
                    namespace=namespace,
                    resource_kind="Service",
                    resource_name=service_name,
                    issue="Service is exposed using type LoadBalancer",
                    reason=["spec.type=LoadBalancer"],
                    recommendation="Confirm this Service must be externally exposed. Prefer ClusterIP plus Ingress with TLS and authentication where possible.",
                    remediation_type="documentation",
                ))

            if self.rules.get("flagNodePortServices", True) and service_type == "NodePort":
                findings.append(SecurityFindingModel(
                    name=f"{namespace}-{service_name}-nodeport-exposure",
                    severity="medium",
                    category="network-security",
                    namespace=namespace,
                    resource_kind="Service",
                    resource_name=service_name,
                    issue="Service is exposed using type NodePort",
                    reason=["spec.type=NodePort"],
                    recommendation="Avoid NodePort unless required. Prefer ClusterIP plus controlled ingress gateway.",
                    remediation_type="documentation",
                ))

            for port in service.spec.ports or []:
                port_number = port.port
                node_port = port.node_port

                if self.rules.get("flagSensitiveExposedPorts", True):
                    if port_number in SENSITIVE_PORTS:
                        findings.append(self.sensitive_port_finding(
                            namespace=namespace,
                            resource_kind="Service",
                            resource_name=service_name,
                            port=port_number,
                            service_name=SENSITIVE_PORTS[port_number],
                        ))

                    if node_port in SENSITIVE_PORTS:
                        findings.append(self.sensitive_port_finding(
                            namespace=namespace,
                            resource_kind="Service",
                            resource_name=service_name,
                            port=node_port,
                            service_name=SENSITIVE_PORTS[node_port],
                        ))

        return findings

    def scan_ingresses(self, namespace: str) -> List[SecurityFindingModel]:
        findings: List[SecurityFindingModel] = []

        if not self.rules.get("requireIngressTLS", True):
            return findings

        try:
            ingresses = self.networking_api.list_namespaced_ingress(namespace=namespace).items
        except client.exceptions.ApiException as exc:
            self.logger.debug(f"Could not list Ingresses in {namespace}: {exc}")
            return findings

        for ingress in ingresses:
            tls = ingress.spec.tls or []

            if len(tls) == 0:
                findings.append(SecurityFindingModel(
                    name=f"{namespace}-{ingress.metadata.name}-ingress-without-tls",
                    severity="medium",
                    category="network-security",
                    namespace=namespace,
                    resource_kind="Ingress",
                    resource_name=ingress.metadata.name,
                    issue="Ingress is exposed without TLS",
                    reason=["spec.tls is empty"],
                    recommendation="Configure TLS for this Ingress using cert-manager or a trusted certificate source.",
                    remediation_type="documentation",
                ))

        return findings

    def scan_traefik_ingressroutes(self, namespace: str) -> List[SecurityFindingModel]:
        findings: List[SecurityFindingModel] = []

        if not self.rules.get("requireTraefikIngressRouteTLS", True):
            return findings

        try:
            result = self.custom_api.list_namespaced_custom_object(
                group="traefik.io",
                version="v1alpha1",
                namespace=namespace,
                plural="ingressroutes",
            )
        except client.exceptions.ApiException as exc:
            self.logger.debug(f"Could not list Traefik IngressRoutes in {namespace}: {exc}")
            return findings

        for route in result.get("items", []):
            name = route.get("metadata", {}).get("name", "unknown")
            spec = route.get("spec", {})
            tls = spec.get("tls")

            if not tls:
                findings.append(SecurityFindingModel(
                    name=f"{namespace}-{name}-traefik-ingressroute-without-tls",
                    severity="medium",
                    category="network-security",
                    namespace=namespace,
                    resource_kind="IngressRoute",
                    resource_name=name,
                    issue="Traefik IngressRoute is exposed without TLS",
                    reason=["spec.tls is missing"],
                    recommendation="Configure spec.tls for this Traefik IngressRoute.",
                    remediation_type="documentation",
                ))

        return findings

    def sensitive_port_finding(self, namespace: str, resource_kind: str, resource_name: str, port: int, service_name: str) -> SecurityFindingModel:
        return SecurityFindingModel(
            name=f"{namespace}-{resource_name}-sensitive-port-{port}",
            severity="high",
            category="network-security",
            namespace=namespace,
            resource_kind=resource_kind,
            resource_name=resource_name,
            issue=f"Sensitive port {port}/{service_name} is exposed",
            reason=[f"port={port}", f"service={service_name}"],
            recommendation="Restrict this port to internal traffic only, or protect it with strong network policy, authentication, and TLS.",
            remediation_type="documentation",
        )
