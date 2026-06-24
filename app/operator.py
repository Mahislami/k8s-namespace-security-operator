import kopf
from kubernetes import config

from app.security_manager import SecurityManager


SYSTEM_NAMESPACES = {
    "kube-system",
    "kube-public",
    "kube-node-lease",
}


def should_skip_namespace(namespace: str) -> bool:
    """
    Skip noisy Kubernetes system namespaces by default.

    This keeps the demo focused, but the operator can still be configured to
    support them later.
    """
    return namespace in SYSTEM_NAMESPACES


@kopf.on.startup()
def startup(settings: kopf.OperatorSettings, logger, **kwargs):
    """
    Configure Kubernetes API access.

    Local development:
      load_kube_config()

    In-cluster deployment:
      load_incluster_config()
    """
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
    """
    Namespace-level monitoring entrypoint.

    The namespace itself is monitored here. Security posture is then kept fresh
    by watching the security-relevant resources inside the namespace.
    """
    if should_skip_namespace(name):
        return

    logger.info(f"Namespace changed: {name}")
    manager = SecurityManager(logger)
    manager.reconcile_namespace(name)


@kopf.on.create("", "v1", "pods")
@kopf.on.update("", "v1", "pods")
def pod_changed(body, namespace, name, logger, **kwargs):
    """Scan only the changed Pod."""
    if not namespace or should_skip_namespace(namespace):
        return

    logger.info(f"Pod changed: {namespace}/{name}")
    manager = SecurityManager(logger)
    manager.handle_pod_event(body, namespace)


@kopf.on.delete("", "v1", "pods")
def pod_deleted(namespace, name, logger, **kwargs):
    """
    Pod deletion handling.

    A deleted Pod may make old findings stale, so we refresh the namespace.
    """
    if not namespace or should_skip_namespace(namespace):
        return

    logger.info(f"Pod deleted: {namespace}/{name}")
    manager = SecurityManager(logger)
    manager.handle_pod_delete(namespace)


@kopf.on.create("apps", "v1", "deployments")
@kopf.on.update("apps", "v1", "deployments")
def deployment_changed(body, namespace, name, logger, **kwargs):
    """Scan only Deployment.spec.template."""
    if not namespace or should_skip_namespace(namespace):
        return

    logger.info(f"Deployment changed: {namespace}/{name}")
    manager = SecurityManager(logger)
    manager.handle_deployment_event(body, namespace)


@kopf.on.create("", "v1", "serviceaccounts")
@kopf.on.update("", "v1", "serviceaccounts")
@kopf.on.delete("", "v1", "serviceaccounts")
def service_account_changed(namespace, name, logger, **kwargs):
    """ServiceAccount changes can affect namespace security posture."""
    if not namespace or should_skip_namespace(namespace):
        return

    logger.info(f"ServiceAccount changed: {namespace}/{name}")
    manager = SecurityManager(logger)
    manager.reconcile_namespace(namespace)


@kopf.on.create("rbac.authorization.k8s.io", "v1", "rolebindings")
@kopf.on.update("rbac.authorization.k8s.io", "v1", "rolebindings")
@kopf.on.delete("rbac.authorization.k8s.io", "v1", "rolebindings")
def rolebinding_changed(namespace, name, logger, **kwargs):
    """RoleBinding changes can affect namespace RBAC posture."""
    if not namespace or should_skip_namespace(namespace):
        return

    logger.info(f"RoleBinding changed: {namespace}/{name}")
    manager = SecurityManager(logger)
    manager.reconcile_namespace(namespace)


@kopf.on.create("networking.k8s.io", "v1", "networkpolicies")
@kopf.on.update("networking.k8s.io", "v1", "networkpolicies")
@kopf.on.delete("networking.k8s.io", "v1", "networkpolicies")
def network_policy_changed(namespace, name, logger, **kwargs):
    """NetworkPolicy changes affect namespace-level network isolation."""
    if not namespace or should_skip_namespace(namespace):
        return

    logger.info(f"NetworkPolicy changed: {namespace}/{name}")
    manager = SecurityManager(logger)
    manager.reconcile_namespace(namespace)


@kopf.on.create("cilium.io", "v2", "ciliumnetworkpolicies")
@kopf.on.update("cilium.io", "v2", "ciliumnetworkpolicies")
@kopf.on.delete("cilium.io", "v2", "ciliumnetworkpolicies")
def cilium_network_policy_changed(namespace, name, logger, **kwargs):
    """CiliumNetworkPolicy changes affect namespace-level network isolation."""
    if not namespace or should_skip_namespace(namespace):
        return

    logger.info(f"CiliumNetworkPolicy changed: {namespace}/{name}")
    manager = SecurityManager(logger)
    manager.reconcile_namespace(namespace)


@kopf.timer("", "v1", "namespaces", interval=1800.0, sharp=False)
def periodic_namespace_resync(name, logger, **kwargs):
    """
    Periodic consistency reconciliation.

    This catches missed events, operator restarts, or stale reports.
    """
    if should_skip_namespace(name):
        return

    logger.info(f"Periodic namespace resync: {name}")
    manager = SecurityManager(logger)
    manager.reconcile_namespace(name)
