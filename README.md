# Kubernetes Namespace Security Operator

A Kubernetes-native Security Operator built with **Python**, **Kopf**, **Helm**, and **Custom Resource Definitions (CRDs)**.

The operator continuously monitors Kubernetes namespace security posture, detects security misconfigurations, creates findings, derives remediation recommendations, tracks active/resolved lifecycle, and maintains a namespace-level security score.

Unlike periodic scanners or CronJobs, this project follows the Kubernetes **controller/reconciliation pattern**. It reacts to Kubernetes events, marks affected namespaces as dirty, batches noisy events, and reconciles only namespaces that need re-evaluation.

---

## What This Project Does

The operator monitors Kubernetes resources such as:

* Namespaces
* Pods
* Deployments
* DaemonSets
* StatefulSets
* ReplicaSets
* Jobs
* CronJobs
* Services
* Ingresses
* NetworkPolicies
* CiliumNetworkPolicies
* ServiceAccounts
* RoleBindings
* Secrets
* ConfigMaps
* PersistentVolumeClaims
* Container images

It produces Kubernetes-native outputs:

* `SecurityFinding`
* `SecurityRemediation`
* `NamespaceSecurityReport`
* `SecurityPolicyProfile`

---

## Why an Operator Instead of a CronJob?

A CronJob scans periodically:

```text
Every N minutes
    ↓
Scan everything
    ↓
Generate report
```

This creates two problems:

1. Security issues may remain undetected until the next scheduled run.
2. The entire cluster is rescanned even if only one resource changed.

This operator is event-driven:

```text
Resource changes
    ↓
Namespace marked dirty
    ↓
Dirty worker batches events
    ↓
Only affected namespace is reconciled
```

Benefits:

* Near real-time detection
* Lower API server load
* Better scalability
* Kubernetes-native reconciliation model
* Cleaner lifecycle tracking

---

## High-Level Architecture

```text
                         Kubernetes API Server
                                  │
                                  ▼
                         Kopf Event Watchers
                                  │
                                  ▼
                         Namespace Security Operator
                                  │
                                  ▼
                         Dirty Namespace Queue
                                  │
                                  ▼
                         SecurityManager
                                  │
        ┌──────────────┬──────────────┬──────────────┐
        ▼              ▼              ▼              ▼
   Pod Scanner    Image Scanner   Secret Scanner   ...
        │              │              │
        └──────────────┴──────────────┘
                                  │
                                  ▼
                       SecurityFindingModel
                                  │
                                  ▼
                         SecurityManager
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
      SecurityFinding      SecurityRemediation   NamespaceSecurityReport
            CRD                  CRD                    CRD
```

---

## Core Design Principle

The operator itself contains no security logic.

Its responsibilities are:

* Watch Kubernetes resources
* Detect resource events
* Mark namespaces dirty
* Start background workers
* Delegate reconciliation to `SecurityManager`

The `SecurityManager` is responsible for:

* Loading the security profile
* Running scanners
* Aggregating findings
* Creating or updating `SecurityFinding` CRDs
* Resolving obsolete findings
* Deriving `SecurityRemediation` CRDs from findings
* Calculating namespace score
* Updating `NamespaceSecurityReport`
* Cleaning up expired resolved objects

---

## Startup Mechanism

When the operator starts, the following sequence happens:

```text
Helm install / upgrade
    ↓
Kubernetes Deployment created
    ↓
Operator Pod starts
    ↓
Container runs: kopf run app/operator.py
    ↓
Python imports modules
    ↓
Global memory structures are created
    ↓
Kopf startup handler runs
    ↓
Kubernetes config is loaded
    ↓
Environment variables are read
    ↓
Background workers are started
    ↓
Existing namespaces are seeded as dirty
    ↓
Event handlers watch Kubernetes resources
```

The startup handler creates two background tasks:

```python
asyncio.create_task(dirty_worker(logger))
asyncio.create_task(full_resync_worker(logger))
```

### 1. `dirty_worker`

This is the main reconciliation worker.

It:

* wakes up every `DIRTY_WORKER_INTERVAL_SECONDS`
* checks `DIRTY_NAMESPACES`
* reconciles namespaces when threshold or timer conditions are met
* calls `SecurityManager.reconcile_namespace(namespace)`

### 2. `full_resync_worker`

This is a safety mechanism.

It:

* wakes up every `FULL_RESYNC_SECONDS`
* lists namespaces
* marks allowed namespaces dirty using reason `periodic-full-resync`
* does not scan directly

All reconciliation still flows through the `dirty_worker`.

---

## Dirty Namespace Mechanism

Instead of scanning immediately after every event, the operator marks a namespace as dirty.

```text
Pod changed
    ↓
resource_event()
    ↓
mark_namespace_dirty()
    ↓
DIRTY_NAMESPACES[namespace]
```

Example dirty entry:

```python
{
  "first_seen": 1782465976,
  "last_seen": 1782465980,
  "count": 7,
  "reasons": {
    "deployment-changed:risky-deployment",
    "pod-changed:risky-pod",
    "secret-changed:risky-secret"
  },
  "retry_after": 0
}
```

This avoids repeated scans during noisy rollouts.

Example:

```text
50 Kubernetes events
    ↓
1 dirty namespace entry
    ↓
1 reconciliation
```

---

## Concurrency and Safety

The operator uses a producer/consumer model:

```text
Event handlers        ┐
full_resync_worker    ├── mark namespaces dirty
startup seed          ┘
        ↓
DIRTY_NAMESPACES
        ↓
dirty_worker
        ↓
SecurityManager
```

Safety is provided by:

```python
DIRTY_LOCK = asyncio.Lock()
```

All reads and writes to `DIRTY_NAMESPACES` are protected by this lock.

Important properties:

* Multiple producers can mark namespaces dirty.
* Only one worker consumes dirty namespaces.
* Only one namespace is reconciled at a time.
* Reconciliation is serial and deterministic.
* Long-running reconciliation is executed with `asyncio.to_thread()` so the event loop is not blocked.

---

## Reconciliation Flow

When a namespace is reconciled:

```text
dirty_worker
    ↓
reconcile_namespace(namespace)
    ↓
SecurityManager
    ↓
Load SecurityPolicyProfile
    ↓
Run all scanners
    ↓
Collect SecurityFindingModel objects
    ↓
Compare new findings with existing SecurityFinding CRDs
    ↓
Create new findings
    ↓
Keep existing findings active
    ↓
Mark missing findings resolved
    ↓
Derive/update remediations
    ↓
Calculate namespace score
    ↓
Update NamespaceSecurityReport
    ↓
Cleanup expired resolved findings/remediations
```

Reconciliation is idempotent:

> Running reconciliation multiple times without changing the cluster produces the same final security state.

---

## SecurityManager

The `SecurityManager` is the central orchestration layer.

It is the only component that writes CRDs.

Scanners only return `SecurityFindingModel` objects.

This design keeps scanners simple and reusable.

```text
Scanner
    ↓
SecurityFindingModel
    ↓
SecurityManager
    ├── SecurityFinding CRD
    ├── SecurityRemediation CRD
    └── NamespaceSecurityReport CRD
```

There is no separate `SecurityRemediationModel`.

Remediation is derived from the finding.

---

## Scanner Framework

Each scanner has one responsibility.

Current scanners include:

| Scanner            | Purpose                                                 |
| ------------------ | ------------------------------------------------------- |
| NamespaceScanner   | Pod Security Admission labels and namespace posture     |
| PodScanner         | Standalone Pod security                                 |
| DeploymentScanner  | Deployment pod template security                        |
| DaemonSetScanner   | DaemonSet pod template security                         |
| StatefulSetScanner | StatefulSet pod template security                       |
| ReplicaSetScanner  | ReplicaSet pod template security                        |
| JobScanner         | Job pod template security                               |
| CronJobScanner     | CronJob jobTemplate security                            |
| NetworkScanner     | NetworkPolicy, NodePort, LoadBalancer, Ingress exposure |
| RBACScanner        | ServiceAccount/RBAC-related checks                      |
| ImageScanner       | latest tag, missing tag, mutable images                 |
| SecretScanner      | risky Secret patterns                                   |
| ConfigMapScanner   | sensitive-looking ConfigMap keys                        |
| StorageScanner     | PVC/storage configuration                               |

Scanners do not create Kubernetes resources directly.

They only return findings.

---

## Finding Lifecycle

```text
Issue detected
    ↓
SecurityFinding created
    ↓
State = Active
    ↓
Issue fixed
    ↓
Finding no longer appears in latest scan
    ↓
State = Resolved
    ↓
Retention period expires
    ↓
Finding deleted
```

Resolved findings are retained for audit purposes.

They do not affect namespace score.

---

## Active vs Resolved Findings

The `NamespaceSecurityReport` is calculated only from **Active** findings.

Resolved findings remain visible for history, but they do not affect:

* Score
* Posture
* Active finding count

Commands:

```bash
kubectl get sf -n security-operator-demo -l security.meslami.io/state=active
kubectl get sf -n security-operator-demo -l security.meslami.io/state=resolved
```

---

## SecurityRemediation Lifecycle

A `SecurityRemediation` is derived from a `SecurityFinding`.

When a finding is active, the remediation is active.

When a finding becomes resolved, the remediation becomes resolved.

```text
SecurityFinding Active
    ↓
SecurityRemediation Active

SecurityFinding Resolved
    ↓
SecurityRemediation Resolved
```

Commands:

```bash
kubectl get sr -A
kubectl get sr -n security-operator-demo -l security.meslami.io/state=active
kubectl get sr -n security-operator-demo -l security.meslami.io/state=resolved
```

---

## Namespace Security Report

Each namespace gets one `NamespaceSecurityReport`.

Example:

```bash
kubectl get nsr -A
```

Example output:

```text
NAMESPACE                NAME                     SCORE   POSTURE    FINDINGS   UNIQUE
default                  default                  94      Healthy    2          2
logging-system           logging-system           65      Risky      14         10
platform-system          platform-system          20      Critical   32         31
security-operator-demo   security-operator-demo   47      Risky      15         15
```

---

## Scoring

The score starts at 100.

Only Active findings are counted.

Example penalty model:

```text
Critical  → -30
High      → -15
Medium    → -6
Low       → -2
Info      →  0
```

Posture:

| Score  | Posture  |
| ------ | -------- |
| 85–100 | Healthy  |
| 70–84  | Moderate |
| 40–69  | Risky    |
| 0–39   | Critical |

---

## Supported Security Checks

Current checks include:

* Privileged containers
* hostNetwork
* hostPID
* hostPath volumes
* Missing runAsNonRoot
* Default ServiceAccount usage
* Missing NetworkPolicy
* NodePort exposure
* LoadBalancer exposure
* Ingress exposure
* Missing Pod Security Admission labels
* latest image tag
* missing image tag
* mutable image references
* sensitive-looking ConfigMap keys
* risky Secret patterns
* PVC/storage configuration issues

---

## CRDs

### SecurityPolicyProfile

Defines namespace security policy.

### SecurityFinding

Represents one detected issue.

### SecurityRemediation

Represents recommended action derived from a finding.

### NamespaceSecurityReport

Represents aggregated namespace posture.

---

## Runtime Configuration

The operator is configured through environment variables generated by Helm values.

| Environment Variable                | Description                                                      |
| ----------------------------------- | ---------------------------------------------------------------- |
| WATCH_NAMESPACES                    | Comma-separated namespaces to watch. Empty means all namespaces. |
| EXCLUDE_NAMESPACES                  | Namespaces to ignore.                                            |
| DIRTY_EVENT_THRESHOLD               | Number of events before immediate reconcile.                     |
| DIRTY_FLUSH_SECONDS                 | Maximum time a namespace can remain dirty.                       |
| DIRTY_WORKER_INTERVAL_SECONDS       | How often dirty worker wakes up.                                 |
| RETRY_BACKOFF_SECONDS               | Delay before retrying failed reconcile.                          |
| FULL_RESYNC_SECONDS                 | Periodic safety resync interval.                                 |
| RESOLVED_FINDING_RETENTION_DAYS     | Retention for resolved findings.                                 |
| RESOLVED_REMEDIATION_RETENTION_DAYS | Retention for resolved remediations.                             |
| LOG_LEVEL                           | Operator log level.                                              |

View current values:

```bash
kubectl get deploy namespace-security-operator \
  -n security-operator-demo \
  -o jsonpath='{range .spec.template.spec.containers[0].env[*]}{.name}={.value}{"\n"}{end}'
```

---

# Installation

## Prerequisites

Required tools:

```bash
kubectl
helm
docker
python3
```

Check cluster access:

```bash
kubectl get nodes
kubectl get ns
```

---

## Create Namespace

Create the operator namespace:

```bash
./scripts/create-namespace.sh security-operator-demo
```

Or manually:

```bash
kubectl create namespace security-operator-demo --dry-run=client -o yaml | kubectl apply -f -
```

---

## Install Operator with Helm

Install watching only the demo namespace:

```bash
helm upgrade --install namespace-security-operator \
  charts/namespace-security-operator \
  -n security-operator-demo \
  --create-namespace \
  --set image.repository="mahdislami/namespace-security-operator" \
  --set image.tag="latest" \
  --set image.pullPolicy="Always" \
  --set operator.namespace="security-operator-demo" \
  --set operator.watchNamespaces="security-operator-demo" \
  --set operator.resolvedFindingRetentionDays="30"
```

Install watching all namespaces:

```bash
helm upgrade --install namespace-security-operator \
  charts/namespace-security-operator \
  -n security-operator-demo \
  --create-namespace \
  --set image.repository="mahdislami/namespace-security-operator" \
  --set image.tag="latest" \
  --set image.pullPolicy="Always" \
  --set operator.namespace="security-operator-demo" \
  --set operator.watchNamespaces="" \
  --set operator.resolvedFindingRetentionDays="30"
```

For noisy namespaces, exclude them:

```bash
--set operator.excludeNamespaces="kube-system,kube-public,kube-node-lease,platform-system"
```

---

## Verify Installation

```bash
kubectl get pods -n security-operator-demo
kubectl get deployment -n security-operator-demo
kubectl get crd | grep security.meslami.io
kubectl logs -n security-operator-demo deployment/namespace-security-operator --tail=100
```

---

## Operator Logs

```bash
kubectl logs -n security-operator-demo deployment/namespace-security-operator -f --tail=150
```

If multiple pods exist:

```bash
kubectl logs -n security-operator-demo \
  -l app.kubernetes.io/name=namespace-security-operator \
  --all-containers=true \
  -f --tail=150
```

---

## Stop, Start, Restart

Stop:

```bash
kubectl scale deployment namespace-security-operator \
  -n security-operator-demo \
  --replicas=0
```

Start:

```bash
kubectl scale deployment namespace-security-operator \
  -n security-operator-demo \
  --replicas=1
```

Restart:

```bash
kubectl rollout restart deployment namespace-security-operator \
  -n security-operator-demo
```

Rollout status:

```bash
kubectl rollout status deployment namespace-security-operator \
  -n security-operator-demo
```

---

## Build and Push Image

During active development, use `latest` with `imagePullPolicy=Always`.

```bash
docker build --no-cache -t mahdislami/namespace-security-operator:latest .
docker push mahdislami/namespace-security-operator:latest
```

Recommended production approach:

```bash
docker build --no-cache -t mahdislami/namespace-security-operator:v1.0.0 .
docker push mahdislami/namespace-security-operator:v1.0.0
```

Then deploy:

```bash
--set image.tag="v1.0.0" \
--set image.pullPolicy="IfNotPresent"
```

Avoid `latest` with `IfNotPresent`, because Kubernetes may reuse an old cached image.

---

# Scripts

Scripts are stored under:

```text
scripts/
```

Recommended scripts:

```text
scripts/
├── create-namespace.sh
├── unblock-namespace-if-terminating.sh
├── install-operator.sh
├── clean-test-resources.sh
├── run-insecure-test.sh
├── run-secure-test.sh
├── operator-logs.sh
├── stop-operator.sh
└── start-operator.sh
```

Make executable:

```bash
chmod +x scripts/*.sh
```

---

# Testing

The project includes two test manifests:

```text
comprehensive-insecure-test.yaml
comprehensive-secure-test.yaml
```

Important:

Do not include the `Namespace` object in these test files if the operator runs in the same namespace.

The namespace should be managed separately by scripts or Helm.

---

## Test Flow

### 1. Create namespace

```bash
./scripts/create-namespace.sh security-operator-demo
```

### 2. Install operator

```bash
./scripts/install-operator.sh security-operator-demo security-operator-demo
```

### 3. Clean previous test resources

```bash
./scripts/clean-test-resources.sh security-operator-demo
```

### 4. Watch logs

In a separate terminal:

```bash
./scripts/operator-logs.sh security-operator-demo
```

### 5. Apply insecure resources

```bash
./scripts/run-insecure-test.sh security-operator-demo
```

Expected:

```bash
kubectl get sf -n security-operator-demo -l security.meslami.io/state=active
kubectl get sr -n security-operator-demo -l security.meslami.io/state=active
kubectl get nsr -n security-operator-demo
```

You should see active findings and a reduced namespace score.

### 6. Apply secure resources

```bash
./scripts/run-secure-test.sh security-operator-demo
```

Expected:

```bash
kubectl get sf -n security-operator-demo -l security.meslami.io/state=active
kubectl get sf -n security-operator-demo -l security.meslami.io/state=resolved
kubectl get sr -n security-operator-demo -l security.meslami.io/state=resolved
kubectl get nsr -n security-operator-demo
```

You should see many findings become resolved and the namespace score improve.

---

## Useful Commands

View reports:

```bash
kubectl get nsr -A
kubectl describe nsr security-operator-demo -n security-operator-demo
```

View findings:

```bash
kubectl get sf -A
kubectl get sf -n security-operator-demo
kubectl get sf -n security-operator-demo -l security.meslami.io/state=active
kubectl get sf -n security-operator-demo -l security.meslami.io/state=resolved
```

View remediations:

```bash
kubectl get sr -A
kubectl get sr -n security-operator-demo
kubectl get sr -n security-operator-demo -l security.meslami.io/state=active
kubectl get sr -n security-operator-demo -l security.meslami.io/state=resolved
```

Watch namespace report:

```bash
watch -n 3 'kubectl get nsr -n security-operator-demo'
```

Watch active findings:

```bash
watch -n 3 'kubectl get sf -n security-operator-demo -l security.meslami.io/state=active'
```

Check Helm values:

```bash
helm get values namespace-security-operator -n security-operator-demo
helm get values namespace-security-operator -n security-operator-demo --all
```

Check running image and pull policy:

```bash
kubectl get deploy namespace-security-operator \
  -n security-operator-demo \
  -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}{.spec.template.spec.containers[0].imagePullPolicy}{"\n"}'
```

---

# Namespace Recovery

If the namespace was accidentally deleted and gets stuck in `Terminating`, check it:

```bash
kubectl get ns security-operator-demo -o yaml
```

If blocked by finalizers, remove them:

```bash
kubectl patch namespace security-operator-demo \
  --type=json \
  -p='[{"op":"remove","path":"/metadata/finalizers"}]'
```

Then recreate:

```bash
./scripts/create-namespace.sh security-operator-demo
```

---

# Project Structure

```text
k8s-security-operator/
├── app/
│   ├── operator.py
│   ├── security_manager.py
│   ├── models.py
│   ├── scoring.py
│   ├── utils.py
│   └── scanners/
│       ├── namespace_scanner.py
│       ├── pod_scanner.py
│       ├── deployment_scanner.py
│       ├── daemonset_scanner.py
│       ├── statefulset_scanner.py
│       ├── replicaset_scanner.py
│       ├── job_scanner.py
│       ├── cronjob_scanner.py
│       ├── network_scanner.py
│       ├── rbac_scanner.py
│       ├── image_scanner.py
│       ├── secret_scanner.py
│       ├── configmap_scanner.py
│       └── storage_scanner.py
│
├── charts/
│   └── namespace-security-operator/
│       ├── Chart.yaml
│       ├── values.yaml
│       ├── crds/
│       └── templates/
│
├── examples/
│   ├── comprehensive-insecure-test.yaml
│   └── comprehensive-secure-test.yaml
│
├── scripts/
│   ├── create-namespace.sh
│   ├── unblock-namespace-if-terminating.sh
│   ├── install-operator.sh
│   ├── clean-test-resources.sh
│   ├── run-insecure-test.sh
│   ├── run-secure-test.sh
│   ├── operator-logs.sh
│   ├── stop-operator.sh
│   └── start-operator.sh
│
├── Dockerfile
├── requirements.txt
└── README.md
```

---

# Current Limitations

* Reconciliation is currently serial.
* Expensive vulnerability scanning is not yet integrated.
* Runtime security detection is outside the current scope.
* Network checks focus on exposure and policy presence, not traffic behaviour.
* `latest` images may require `imagePullPolicy=Always` during development.
* Namespace deletion should be handled carefully if the operator runs in the same namespace.

---

# Future Roadmap

* Trivy image vulnerability scanning
* Kubescape integration
* Falco runtime events
* Prometheus metrics
* Grafana dashboards
* Admission webhook mode
* OPA/Gatekeeper integration
* Informer cache
* Parallel namespace workers
* Namespace-level locking
* Web dashboard
* Multi-cluster support
* Historical trend reporting

---

# Design Principles

This project follows:

* Kubernetes Controller Pattern
* Reconciliation Pattern
* Event-driven processing
* Producer/consumer queue model
* Single Responsibility Principle
* Modular scanner design
* Kubernetes-native persistence using CRDs
* Idempotent reconciliation
* Active/resolved lifecycle tracking
* Namespace-level aggregation

The result is a modular, extensible, and Kubernetes-native security platform for continuously assessing namespace security posture while minimising API server load.
