import asyncio
import logging
import os
import time
import warnings
from typing import Dict

import kopf
import urllib3
from kubernetes import client, config

from app.security_manager import SecurityManager


DIRTY_NAMESPACES: Dict[str, dict] = {}
DIRTY_LOCK = asyncio.Lock()
SECURITY_MANAGER = None


def env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name) or str(default))
    except ValueError:
        return default


WATCH_NAMESPACES = {
    ns.strip()
    for ns in (os.getenv("WATCH_NAMESPACES") or "").split(",")
    if ns.strip()
}

EXCLUDE_NAMESPACES = {
    ns.strip()
    for ns in (
        os.getenv("EXCLUDE_NAMESPACES")
        or "kube-system,kube-public,kube-node-lease"
    ).split(",")
    if ns.strip()
}

DIRTY_EVENT_THRESHOLD = env_int("DIRTY_EVENT_THRESHOLD", 20)
DIRTY_FLUSH_SECONDS = env_int("DIRTY_FLUSH_SECONDS", 20)
DIRTY_WORKER_INTERVAL_SECONDS = env_int("DIRTY_WORKER_INTERVAL_SECONDS", 5)
RETRY_BACKOFF_SECONDS = env_int("RETRY_BACKOFF_SECONDS", 120)
FULL_RESYNC_SECONDS = env_int("FULL_RESYNC_SECONDS", 1800)
LOG_LEVEL = (os.getenv("LOG_LEVEL") or "INFO").upper()


def configure_logging():
    logging.getLogger().setLevel(LOG_LEVEL)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("kubernetes").setLevel(logging.WARNING)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)


def should_process_namespace(namespace: str) -> bool:
    if not namespace:
        return False

    if namespace in EXCLUDE_NAMESPACES:
        return False

    if WATCH_NAMESPACES and namespace not in WATCH_NAMESPACES:
        return False

    return True


def should_ignore_resource(name: str) -> bool:
    if not name:
        return False

    return name.startswith("namespace-security-operator-")


async def mark_namespace_dirty(namespace: str, reason: str, logger):
    if not should_process_namespace(namespace):
        return

    async with DIRTY_LOCK:
        now = time.time()

        if namespace not in DIRTY_NAMESPACES:
            DIRTY_NAMESPACES[namespace] = {
                "first_seen": now,
                "last_seen": now,
                "count": 0,
                "reasons": set(),
                "retry_after": 0,
            }

        item = DIRTY_NAMESPACES[namespace]
        item["last_seen"] = now
        item["count"] += 1
        item["reasons"].add(reason)

        logger.info(
            f"Marked namespace dirty: {namespace}, "
            f"reason={reason}, count={item['count']}"
        )


def reconcile_namespace(namespace: str, logger):
    global SECURITY_MANAGER

    if SECURITY_MANAGER is None:
        SECURITY_MANAGER = SecurityManager(logger)

    SECURITY_MANAGER.reconcile_namespace(namespace)


async def dirty_worker(logger):
    while True:
        await asyncio.sleep(DIRTY_WORKER_INTERVAL_SECONDS)

        namespace_to_reconcile = None
        item_snapshot = None

        async with DIRTY_LOCK:
            now = time.time()

            for namespace, item in list(DIRTY_NAMESPACES.items()):
                if item.get("retry_after", 0) > now:
                    continue

                age = now - item["first_seen"]
                count = item["count"]

                if count >= DIRTY_EVENT_THRESHOLD or age >= DIRTY_FLUSH_SECONDS:
                    namespace_to_reconcile = namespace
                    item_snapshot = item
                    del DIRTY_NAMESPACES[namespace]
                    break

        if not namespace_to_reconcile:
            continue

        reasons = sorted(item_snapshot.get("reasons", set()))
        count = item_snapshot.get("count", 0)

        logger.info(
            f"Reconciling dirty namespace: {namespace_to_reconcile}, "
            f"coalescedEvents={count}, reasons={reasons}"
        )

        try:
            await asyncio.to_thread(
                reconcile_namespace,
                namespace_to_reconcile,
                logger,
            )
        except Exception as exc:
            logger.exception(
                f"Failed to reconcile dirty namespace {namespace_to_reconcile}: {exc}"
            )

            async with DIRTY_LOCK:
                DIRTY_NAMESPACES[namespace_to_reconcile] = {
                    "first_seen": time.time(),
                    "last_seen": time.time(),
                    "count": 1,
                    "reasons": {"reconcile-retry"},
                    "retry_after": time.time() + RETRY_BACKOFF_SECONDS,
                }


async def full_resync_worker(logger):
    while True:
        await asyncio.sleep(FULL_RESYNC_SECONDS)

        try:
            core_api = client.CoreV1Api()
            namespaces = core_api.list_namespace().items
        except Exception as exc:
            logger.warning(f"Failed to list namespaces for full resync: {exc}")
            continue

        for ns in namespaces:
            name = ns.metadata.name
            if should_process_namespace(name):
                await mark_namespace_dirty(name, "periodic-full-resync", logger)


async def resource_event(resource_namespace, resource_name, resource_type, logger, **kwargs):
    if not should_process_namespace(resource_namespace):
        return

    if should_ignore_resource(resource_name):
        return

    body = kwargs.get("body") or {}
    metadata = body.get("metadata", {}) if isinstance(body, dict) else {}

    if metadata.get("deletionTimestamp"):
        logger.info(f"{resource_type} deleting: {resource_namespace}/{resource_name}")
        await mark_namespace_dirty(
            resource_namespace,
            f"{resource_type}-deleted:{resource_name}",
            logger,
        )
        return

    logger.info(f"{resource_type} changed: {resource_namespace}/{resource_name}")
    await mark_namespace_dirty(
        resource_namespace,
        f"{resource_type}-changed:{resource_name}",
        logger,
    )


@kopf.on.startup()
async def startup(settings: kopf.OperatorSettings, logger, **kwargs):
    configure_logging()

    settings.persistence.finalizer = None
    settings.persistence.progress_storage = kopf.AnnotationsProgressStorage()

    try:
        config.load_incluster_config()
        logger.info("Loaded in-cluster Kubernetes configuration")
    except config.ConfigException:
        config.load_kube_config()
        logger.info("Loaded local kubeconfig")

    logger.info(
        "Namespace Security Operator started "
        f"WATCH_NAMESPACES={sorted(WATCH_NAMESPACES) if WATCH_NAMESPACES else 'ALL'} "
        f"EXCLUDE_NAMESPACES={sorted(EXCLUDE_NAMESPACES)} "
        f"DIRTY_EVENT_THRESHOLD={DIRTY_EVENT_THRESHOLD} "
        f"DIRTY_FLUSH_SECONDS={DIRTY_FLUSH_SECONDS} "
        f"DIRTY_WORKER_INTERVAL_SECONDS={DIRTY_WORKER_INTERVAL_SECONDS} "
        f"RETRY_BACKOFF_SECONDS={RETRY_BACKOFF_SECONDS} "
        f"FULL_RESYNC_SECONDS={FULL_RESYNC_SECONDS}"
    )

    asyncio.create_task(dirty_worker(logger))
    asyncio.create_task(full_resync_worker(logger))

    core_api = client.CoreV1Api()
    namespaces = core_api.list_namespace().items

    for ns in namespaces:
        name = ns.metadata.name
        if should_process_namespace(name):
            await mark_namespace_dirty(name, "startup-seed", logger)


@kopf.on.event("", "v1", "namespaces")
async def namespace_event(name, logger, **kwargs):
    await resource_event(name, name, "namespace", logger)


@kopf.on.event("", "v1", "pods")
async def pod_event(namespace, name, logger, **kwargs):
    await resource_event(namespace, name, "pod", logger, **kwargs)


@kopf.on.event("apps", "v1", "deployments")
async def deployment_event(namespace, name, logger, **kwargs):
    await resource_event(namespace, name, "deployment", logger, **kwargs)


@kopf.on.event("apps", "v1", "daemonsets")
async def daemonset_event(namespace, name, logger, **kwargs):
    await resource_event(namespace, name, "daemonset", logger, **kwargs)


@kopf.on.event("apps", "v1", "statefulsets")
async def statefulset_event(namespace, name, logger, **kwargs):
    await resource_event(namespace, name, "statefulset", logger, **kwargs)


@kopf.on.event("apps", "v1", "replicasets")
async def replicaset_event(namespace, name, logger, **kwargs):
    await resource_event(namespace, name, "replicaset", logger, **kwargs)


@kopf.on.event("batch", "v1", "jobs")
async def job_event(namespace, name, logger, **kwargs):
    await resource_event(namespace, name, "job", logger, **kwargs)


@kopf.on.event("batch", "v1", "cronjobs")
async def cronjob_event(namespace, name, logger, **kwargs):
    await resource_event(namespace, name, "cronjob", logger, **kwargs)


@kopf.on.event("", "v1", "services")
async def service_event(namespace, name, logger, **kwargs):
    await resource_event(namespace, name, "service", logger, **kwargs)


@kopf.on.event("", "v1", "serviceaccounts")
async def service_account_event(namespace, name, logger, **kwargs):
    await resource_event(namespace, name, "serviceaccount", logger, **kwargs)


@kopf.on.event("", "v1", "secrets")
async def secret_event(namespace, name, logger, **kwargs):
    await resource_event(namespace, name, "secret", logger, **kwargs)


@kopf.on.event("", "v1", "configmaps")
async def configmap_event(namespace, name, logger, **kwargs):
    await resource_event(namespace, name, "configmap", logger, **kwargs)


@kopf.on.event("", "v1", "persistentvolumeclaims")
async def pvc_event(namespace, name, logger, **kwargs):
    await resource_event(namespace, name, "pvc", logger, **kwargs)


@kopf.on.event("networking.k8s.io", "v1", "networkpolicies")
async def network_policy_event(namespace, name, logger, **kwargs):
    await resource_event(namespace, name, "networkpolicy", logger, **kwargs)


@kopf.on.event("networking.k8s.io", "v1", "ingresses")
async def ingress_event(namespace, name, logger, **kwargs):
    await resource_event(namespace, name, "ingress", logger, **kwargs)


@kopf.on.event("rbac.authorization.k8s.io", "v1", "rolebindings")
async def rolebinding_event(namespace, name, logger, **kwargs):
    await resource_event(namespace, name, "rolebinding", logger, **kwargs)


@kopf.on.event("cilium.io", "v2", "ciliumnetworkpolicies")
async def cilium_network_policy_event(namespace, name, logger, **kwargs):
    await resource_event(namespace, name, "ciliumnetworkpolicy", logger, **kwargs)


@kopf.on.event("traefik.io", "v1alpha1", "ingressroutes")
async def ingressroute_event(namespace, name, logger, **kwargs):
    await resource_event(namespace, name, "ingressroute", logger, **kwargs)