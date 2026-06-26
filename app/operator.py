import os
import time
import threading
import urllib3

import kopf
from kubernetes import client, config

from app.security_manager import SecurityManager


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


DEFAULT_EXCLUDE_NAMESPACES = {
    "kube-system",
    "kube-public",
    "kube-node-lease",
}


def parse_csv_env(name: str) -> set:
    value = os.getenv(name, "")
    return {item.strip() for item in value.split(",") if item.strip()}


def parse_int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def parse_float_env(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


WATCH_NAMESPACES = parse_csv_env("WATCH_NAMESPACES")
EXCLUDE_NAMESPACES = parse_csv_env("EXCLUDE_NAMESPACES") or DEFAULT_EXCLUDE_NAMESPACES

DIRTY_EVENT_THRESHOLD = parse_int_env("DIRTY_EVENT_THRESHOLD", 10)
DIRTY_FLUSH_SECONDS = parse_float_env("DIRTY_FLUSH_SECONDS", 10.0)
DIRTY_WORKER_INTERVAL_SECONDS = parse_float_env("DIRTY_WORKER_INTERVAL_SECONDS", 2.0)
FULL_RESYNC_SECONDS = parse_float_env("FULL_RESYNC_SECONDS", 1800.0)
RETRY_BACKOFF_SECONDS = parse_float_env("RETRY_BACKOFF_SECONDS", 60.0)

DIRTY_NAMESPACES = {}
DIRTY_LOCK = threading.Lock()
RECONCILE_LOCK = threading.Lock()

SECURITY_MANAGER = None


def should_skip_namespace(namespace: str) -> bool:
    if namespace in EXCLUDE_NAMESPACES:
        return True

    if WATCH_NAMESPACES and namespace not in WATCH_NAMESPACES:
        return True

    return False


def mark_namespace_dirty(namespace: str, reason: str, logger, delay_seconds: float = 0.0):
    if not namespace or should_skip_namespace(namespace):
        return

    now = time.time()
    first_seen = now + delay_seconds

    with DIRTY_LOCK:
        if namespace not in DIRTY_NAMESPACES:
            DIRTY_NAMESPACES[namespace] = {
                "count": 0,
                "first_seen": first_seen,
                "reasons": set(),
            }

        DIRTY_NAMESPACES[namespace]["count"] += 1
        DIRTY_NAMESPACES[namespace]["reasons"].add(reason)
        count = DIRTY_NAMESPACES[namespace]["count"]

    logger.info(f"Marked namespace dirty: {namespace}, reason={reason}, count={count}")


def reconcile_namespace(namespace: str, logger):
    global SECURITY_MANAGER

    if SECURITY_MANAGER is None:
        SECURITY_MANAGER = SecurityManager(logger)

    with RECONCILE_LOCK:
        SECURITY_MANAGER.reconcile_namespace(namespace)


def dirty_worker(logger):
    while True:
        time.sleep(DIRTY_WORKER_INTERVAL_SECONDS)

        now = time.time()
        namespaces_to_flush = []

        with DIRTY_LOCK:
            for namespace, data in list(DIRTY_NAMESPACES.items()):
                age = now - data["first_seen"]

                if age < 0:
                    continue

                if data["count"] >= DIRTY_EVENT_THRESHOLD or age >= DIRTY_FLUSH_SECONDS:
                    namespaces_to_flush.append((namespace, data))
                    DIRTY_NAMESPACES.pop(namespace, None)

        for namespace, data in namespaces_to_flush:
            try:
                logger.info(
                    f"Reconciling dirty namespace: {namespace}, "
                    f"coalescedEvents={data['count']}, "
                    f"reasons={sorted(data['reasons'])}"
                )
                reconcile_namespace(namespace, logger)
            except Exception as exc:
                logger.exception(f"Failed to reconcile dirty namespace {namespace}: {exc}")
                mark_namespace_dirty(
                    namespace,
                    "reconcile-retry",
                    logger,
                    delay_seconds=RETRY_BACKOFF_SECONDS,
                )


def safety_resync_worker(logger):
    while True:
        time.sleep(FULL_RESYNC_SECONDS)

        if WATCH_NAMESPACES:
            namespaces = WATCH_NAMESPACES
        else:
            try:
                core_api = client.CoreV1Api()
                namespaces = {
                    ns.metadata.name
                    for ns in core_api.list_namespace().items
                    if not should_skip_namespace(ns.metadata.name)
                }
            except Exception as exc:
                logger.exception(f"Failed to list namespaces for safety resync: {exc}")
                continue

        for namespace in namespaces:
            if should_skip_namespace(namespace):
                continue

            mark_namespace_dirty(namespace, "periodic-safety-resync", logger)


def seed_existing_namespaces(logger):
    if WATCH_NAMESPACES:
        for namespace in WATCH_NAMESPACES:
            if not should_skip_namespace(namespace):
                mark_namespace_dirty(namespace, "startup-seed", logger)
        return

    core_api = client.CoreV1Api()

    for namespace in core_api.list_namespace().items:
        name = namespace.metadata.name

        if should_skip_namespace(name):
            continue

        mark_namespace_dirty(name, "startup-seed", logger)


def resource_event(namespace, name, resource_type, logger, **kwargs):
    if not namespace:
        return

    event_type = kwargs.get("type", "UNKNOWN")
    mark_namespace_dirty(namespace, f"{resource_type}:{event_type}:{name}", logger)


@kopf.on.startup()
def startup(settings: kopf.OperatorSettings, logger, **kwargs):
    global SECURITY_MANAGER

    try:
        config.load_incluster_config()
        logger.info("Loaded in-cluster Kubernetes configuration")
    except config.ConfigException:
        config.load_kube_config()
        logger.info("Loaded local kubeconfig")

    SECURITY_MANAGER = SecurityManager(logger)

    logger.info("Namespace Security Operator started")
    logger.info(f"Watch namespaces: {WATCH_NAMESPACES or 'cluster-wide'}")
    logger.info(f"Excluded namespaces: {EXCLUDE_NAMESPACES}")
    logger.info(f"Dirty event threshold: {DIRTY_EVENT_THRESHOLD}")
    logger.info(f"Dirty flush seconds: {DIRTY_FLUSH_SECONDS}")
    logger.info(f"Dirty worker interval seconds: {DIRTY_WORKER_INTERVAL_SECONDS}")
    logger.info(f"Full resync seconds: {FULL_RESYNC_SECONDS}")
    logger.info(f"Retry backoff seconds: {RETRY_BACKOFF_SECONDS}")

    seed_existing_namespaces(logger)

    threading.Thread(target=dirty_worker, args=(logger,), daemon=True).start()
    threading.Thread(target=safety_resync_worker, args=(logger,), daemon=True).start()


@kopf.on.event("", "v1", "namespaces")
def namespace_event(name, logger, **kwargs):
    mark_namespace_dirty(name, "namespace-event", logger)


@kopf.on.event("", "v1", "pods")
def pod_event(namespace, name, logger, **kwargs):
    resource_event(namespace, name, "pod", logger, **kwargs)


@kopf.on.event("apps", "v1", "deployments")
def deployment_event(namespace, name, logger, **kwargs):
    resource_event(namespace, name, "deployment", logger, **kwargs)


@kopf.on.event("apps", "v1", "daemonsets")
def daemonset_event(namespace, name, logger, **kwargs):
    resource_event(namespace, name, "daemonset", logger, **kwargs)


@kopf.on.event("apps", "v1", "statefulsets")
def statefulset_event(namespace, name, logger, **kwargs):
    resource_event(namespace, name, "statefulset", logger, **kwargs)


@kopf.on.event("apps", "v1", "replicasets")
def replicaset_event(namespace, name, logger, **kwargs):
    resource_event(namespace, name, "replicaset", logger, **kwargs)


@kopf.on.event("batch", "v1", "jobs")
def job_event(namespace, name, logger, **kwargs):
    resource_event(namespace, name, "job", logger, **kwargs)


@kopf.on.event("batch", "v1", "cronjobs")
def cronjob_event(namespace, name, logger, **kwargs):
    resource_event(namespace, name, "cronjob", logger, **kwargs)


@kopf.on.event("", "v1", "serviceaccounts")
def service_account_event(namespace, name, logger, **kwargs):
    resource_event(namespace, name, "serviceaccount", logger, **kwargs)


@kopf.on.event("", "v1", "services")
def service_event(namespace, name, logger, **kwargs):
    resource_event(namespace, name, "service", logger, **kwargs)


@kopf.on.event("networking.k8s.io", "v1", "ingresses")
def ingress_event(namespace, name, logger, **kwargs):
    resource_event(namespace, name, "ingress", logger, **kwargs)


@kopf.on.event("rbac.authorization.k8s.io", "v1", "rolebindings")
def rolebinding_event(namespace, name, logger, **kwargs):
    resource_event(namespace, name, "rolebinding", logger, **kwargs)


@kopf.on.event("networking.k8s.io", "v1", "networkpolicies")
def network_policy_event(namespace, name, logger, **kwargs):
    resource_event(namespace, name, "networkpolicy", logger, **kwargs)


@kopf.on.event("cilium.io", "v2", "ciliumnetworkpolicies")
def cilium_network_policy_event(namespace, name, logger, **kwargs):
    resource_event(namespace, name, "ciliumnetworkpolicy", logger, **kwargs)


@kopf.on.event("traefik.io", "v1alpha1", "ingressroutes")
def traefik_ingressroute_event(namespace, name, logger, **kwargs):
    resource_event(namespace, name, "traefik-ingressroute", logger, **kwargs)
