import kopf
from kubernetes import config

from app.security_manager import SecurityManager


SYSTEM_NAMESPACES = {
    "kube-system",
    "kube-public",
    "kube-node-lease",
}


def should_skip_namespace(namespace: str) -> bool:
    return namespace in SYSTEM_NAMESPACES


@kopf.on.startup()
def startup(settings: kopf.OperatorSettings, logger, **kwargs):
    try:
        config.load_incluster_config()
        logger.info("Loaded in-cluster Kubernetes configuration")
    except config.ConfigException:
        config.load_kube_config()
        logger.info("Loaded local kubeconfig")

    logger.info("Namespace Security Operator started")


@kopf.on.create("", "v1", "namespaces")
@kopf.on.update("", "v1", "namespaces")
def namespace_changed(name, logger, **kwargs):
    if should_skip_namespace(name):
        return

    logger.info(f"Namespace changed: {name}")
    SecurityManager(logger).reconcile_namespace(name)


@kopf.on.create("", "v1", "pods")
@kopf.on.update("", "v1", "pods")
def pod_changed(body, namespace, name, logger, **kwargs):
    if not namespace or should_skip_namespace(namespace):
        return

    logger.info(f"Pod changed: {namespace}/{name}")
    SecurityManager(logger).handle_pod_event(body, namespace)


@kopf.on.delete("", "v1", "pods")
def pod_deleted(namespace, name, logger, **kwargs):
    if not namespace or should_skip_namespace(namespace):
        return

    logger.info(f"Pod deleted: {namespace}/{name}")
    SecurityManager(logger).handle_pod_delete(namespace)


@kopf.on.create("apps", "v1", "deployments")
@kopf.on.update("apps", "v1", "deployments")
def deployment_changed(body, namespace, name, logger, **kwargs):
    if not namespace or should_skip_namespace(namespace):
        return

    logger.info(f"Deployment changed: {namespace}/{name}")
    SecurityManager(logger).handle_deployment_event(body, namespace)


@kopf.on.create("", "v1", "serviceaccounts")
@kopf.on.update("", "v1", "serviceaccounts")
@kopf.on.delete("", "v1", "serviceaccounts")
def service_account_changed(namespace, name, logger, **kwargs):
    if not namespace or should_skip_namespace(namespace):
        return

    logger.info(f"ServiceAccount changed: {namespace}/{name}")
    SecurityManager(logger).reconcile_namespace(namespace)


@kopf.on.create("", "v1", "services")
@kopf.on.update("", "v1", "services")
@kopf.on.delete("", "v1", "services")
def service_changed(namespace, name, logger, **kwargs):
    if not namespace or should_skip_namespace(namespace):
        return

    logger.info(f"Service changed: {namespace}/{name}")
    SecurityManager(logger).reconcile_namespace(namespace)


@kopf.on.create("networking.k8s.io", "v1", "ingresses")
@kopf.on.update("networking.k8s.io", "v1", "ingresses")
@kopf.on.delete("networking.k8s.io", "v1", "ingresses")
def ingress_changed(namespace, name, logger, **kwargs):
    if not namespace or should_skip_namespace(namespace):
        return

    logger.info(f"Ingress changed: {namespace}/{name}")
    SecurityManager(logger).reconcile_namespace(namespace)


@kopf.on.create("rbac.authorization.k8s.io", "v1", "rolebindings")
@kopf.on.update("rbac.authorization.k8s.io", "v1", "rolebindings")
@kopf.on.delete("rbac.authorization.k8s.io", "v1", "rolebindings")
def rolebinding_changed(namespace, name, logger, **kwargs):
    if not namespace or should_skip_namespace(namespace):
        return

    logger.info(f"RoleBinding changed: {namespace}/{name}")
    SecurityManager(logger).reconcile_namespace(namespace)


@kopf.on.create("networking.k8s.io", "v1", "networkpolicies")
@kopf.on.update("networking.k8s.io", "v1", "networkpolicies")
@kopf.on.delete("networking.k8s.io", "v1", "networkpolicies")
def network_policy_changed(namespace, name, logger, **kwargs):
    if not namespace or should_skip_namespace(namespace):
        return

    logger.info(f"NetworkPolicy changed: {namespace}/{name}")
    SecurityManager(logger).reconcile_namespace(namespace)


@kopf.on.create("cilium.io", "v2", "ciliumnetworkpolicies")
@kopf.on.update("cilium.io", "v2", "ciliumnetworkpolicies")
@kopf.on.delete("cilium.io", "v2", "ciliumnetworkpolicies")
def cilium_network_policy_changed(namespace, name, logger, **kwargs):
    if not namespace or should_skip_namespace(namespace):
        return

    logger.info(f"CiliumNetworkPolicy changed: {namespace}/{name}")
    SecurityManager(logger).reconcile_namespace(namespace)


@kopf.on.create("traefik.io", "v1alpha1", "ingressroutes")
@kopf.on.update("traefik.io", "v1alpha1", "ingressroutes")
@kopf.on.delete("traefik.io", "v1alpha1", "ingressroutes")
def traefik_ingressroute_changed(namespace, name, logger, **kwargs):
    if not namespace or should_skip_namespace(namespace):
        return

    logger.info(f"Traefik IngressRoute changed: {namespace}/{name}")
    SecurityManager(logger).reconcile_namespace(namespace)


@kopf.timer("", "v1", "namespaces", interval=1800.0, sharp=False)
def periodic_namespace_resync(name, logger, **kwargs):
    if should_skip_namespace(name):
        return

    logger.info(f"Periodic namespace resync: {name}")
    SecurityManager(logger).reconcile_namespace(name)
