import kopf
import urllib3

from kubernetes import config

from app.security_manager import SecurityManager


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


SYSTEM_NAMESPACES = {
    "kube-system",
    "kube-public",
    "kube-node-lease"
}


def should_skip_namespace(namespace: str) -> bool:
    return namespace in SYSTEM_NAMESPACES


def is_being_deleted(body: dict) -> bool:
    return body.get("metadata", {}).get("deletionTimestamp") is not None


@kopf.on.startup()
def startup(settings: kopf.OperatorSettings, logger, **kwargs):
    # This operator only scans and reports.
    # It should not attach finalizers to Kubernetes built-in objects.
    settings.persistence.finalizer = "security.meslami.io/finalizer"

    try:
        config.load_incluster_config()
        logger.info("Loaded in-cluster Kubernetes configuration")
    except config.ConfigException:
        config.load_kube_config()
        logger.info("Loaded local kubeconfig")

    logger.info("Namespace Security Operator started")


@kopf.on.create("", "v1", "namespaces")
@kopf.on.update("", "v1", "namespaces")
def namespace_changed(body, name, logger, **kwargs):
    if should_skip_namespace(name):
        return

    if is_being_deleted(body):
        logger.info(f"Skipping terminating Namespace: {name}")
        return

    logger.info(f"Namespace changed: {name}")
    SecurityManager(logger).reconcile_namespace(name)


@kopf.on.create("", "v1", "pods")
@kopf.on.update("", "v1", "pods")
def pod_changed(body, namespace, name, logger, **kwargs):
    if not namespace or should_skip_namespace(namespace):
        return

    if is_being_deleted(body):
        logger.info(f"Skipping terminating Pod: {namespace}/{name}")
        return

    logger.info(f"Pod changed: {namespace}/{name}")
    SecurityManager(logger).handle_pod_event(body, namespace)


@kopf.on.create("apps", "v1", "deployments")
@kopf.on.update("apps", "v1", "deployments")
def deployment_changed(body, namespace, name, logger, **kwargs):
    if not namespace or should_skip_namespace(namespace):
        return

    if is_being_deleted(body):
        logger.info(f"Skipping terminating Deployment: {namespace}/{name}")
        return

    logger.info(f"Deployment changed: {namespace}/{name}")
    SecurityManager(logger).handle_deployment_event(body, namespace)


@kopf.on.create("", "v1", "serviceaccounts")
@kopf.on.update("", "v1", "serviceaccounts")
def service_account_changed(body, namespace, name, logger, **kwargs):
    if not namespace or should_skip_namespace(namespace):
        return

    if is_being_deleted(body):
        logger.info(f"Skipping terminating ServiceAccount: {namespace}/{name}")
        return

    logger.info(f"ServiceAccount changed: {namespace}/{name}")
    SecurityManager(logger).reconcile_namespace(namespace)


@kopf.on.create("", "v1", "services")
@kopf.on.update("", "v1", "services")
def service_changed(body, namespace, name, logger, **kwargs):
    if not namespace or should_skip_namespace(namespace):
        return

    if is_being_deleted(body):
        logger.info(f"Skipping terminating Service: {namespace}/{name}")
        return

    logger.info(f"Service changed: {namespace}/{name}")
    SecurityManager(logger).reconcile_namespace(namespace)


@kopf.on.create("networking.k8s.io", "v1", "ingresses")
@kopf.on.update("networking.k8s.io", "v1", "ingresses")
def ingress_changed(body, namespace, name, logger, **kwargs):
    if not namespace or should_skip_namespace(namespace):
        return

    if is_being_deleted(body):
        logger.info(f"Skipping terminating Ingress: {namespace}/{name}")
        return

    logger.info(f"Ingress changed: {namespace}/{name}")
    SecurityManager(logger).reconcile_namespace(namespace)


@kopf.on.create("rbac.authorization.k8s.io", "v1", "rolebindings")
@kopf.on.update("rbac.authorization.k8s.io", "v1", "rolebindings")
def rolebinding_changed(body, namespace, name, logger, **kwargs):
    if not namespace or should_skip_namespace(namespace):
        return

    if is_being_deleted(body):
        logger.info(f"Skipping terminating RoleBinding: {namespace}/{name}")
        return

    logger.info(f"RoleBinding changed: {namespace}/{name}")
    SecurityManager(logger).reconcile_namespace(namespace)


@kopf.on.create("networking.k8s.io", "v1", "networkpolicies")
@kopf.on.update("networking.k8s.io", "v1", "networkpolicies")
def network_policy_changed(body, namespace, name, logger, **kwargs):
    if not namespace or should_skip_namespace(namespace):
        return

    if is_being_deleted(body):
        logger.info(f"Skipping terminating NetworkPolicy: {namespace}/{name}")
        return

    logger.info(f"NetworkPolicy changed: {namespace}/{name}")
    SecurityManager(logger).reconcile_namespace(namespace)


@kopf.on.create("cilium.io", "v2", "ciliumnetworkpolicies")
@kopf.on.update("cilium.io", "v2", "ciliumnetworkpolicies")
def cilium_network_policy_changed(body, namespace, name, logger, **kwargs):
    if not namespace or should_skip_namespace(namespace):
        return

    if is_being_deleted(body):
        logger.info(f"Skipping terminating CiliumNetworkPolicy: {namespace}/{name}")
        return

    logger.info(f"CiliumNetworkPolicy changed: {namespace}/{name}")
    SecurityManager(logger).reconcile_namespace(namespace)


@kopf.on.create("traefik.io", "v1alpha1", "ingressroutes")
@kopf.on.update("traefik.io", "v1alpha1", "ingressroutes")
def traefik_ingressroute_changed(body, namespace, name, logger, **kwargs):
    if not namespace or should_skip_namespace(namespace):
        return

    if is_being_deleted(body):
        logger.info(f"Skipping terminating Traefik IngressRoute: {namespace}/{name}")
        return

    logger.info(f"Traefik IngressRoute changed: {namespace}/{name}")
    SecurityManager(logger).reconcile_namespace(namespace)


@kopf.timer("", "v1", "namespaces", interval=1800.0, sharp=False)
def periodic_namespace_resync(body, name, logger, **kwargs):
    if should_skip_namespace(name):
        return

    if is_being_deleted(body):
        logger.info(f"Skipping terminating Namespace during periodic resync: {name}")
        return

    logger.info(f"Periodic namespace resync: {name}")
    SecurityManager(logger).reconcile_namespace(name)