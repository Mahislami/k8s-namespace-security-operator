# Kubernetes Namespace Security Operator

A Kubernetes-native Security Operator built with **Python**, **Kopf**, and **Custom Resource Definitions (CRDs)** that continuously monitors namespace security posture, detects Kubernetes security misconfigurations, tracks their lifecycle, generates remediation guidance, and maintains a real-time security score for every namespace.

Unlike traditional scanners that perform scheduled cluster-wide scans, this operator follows the Kubernetes **controller/reconciliation pattern**, making it scalable, event-driven, and suitable for continuously changing environments.

---

# Features

## Continuous Security Monitoring

- Namespace Security
- Pod Security
- Deployment Security
- StatefulSet Security
- DaemonSet Security
- Job Security
- Service Security
- Network Security
- Service Account Security

---

## Security Findings

Automatically creates SecurityFinding CRDs for detected issues.

Each finding contains:

- Severity
- Category
- Resource
- Description
- Recommendation
- State (Active / Resolved)

---

## Namespace Security Report (NSR)

Each namespace maintains a live security report including:

- Security Score
- Security Posture
- Active Findings
- Unique Findings
- Last Updated timestamp

Example:

```
kubectl get nsr -A

NAMESPACE                SCORE   POSTURE   FINDINGS
default                  94      Healthy   2
logging-system           65      Risky     14
platform-system          20      Critical  32
```

---

## Security Remediation

For every finding the operator automatically creates a SecurityRemediation CR.

Supported remediation types include

- Manifest patches
- Commands
- Documentation
- ServiceAccount changes
- NetworkPolicy suggestions

---

## Event Driven Architecture

The operator never performs unnecessary full cluster scans.

Instead it reacts to Kubernetes events.

Examples

```
Pod Updated
        │
        ▼
Scan only that Pod
```

```
Deployment Updated
        │
        ▼
Scan only Deployment Template
```

```
DaemonSet Updated
        │
        ▼
Scan only that DaemonSet
```

```
NetworkPolicy Created
        │
        ▼
Reconcile Namespace
```

This dramatically reduces Kubernetes API usage compared to rescanning everything.

---

# Overall Architecture

```
                     Kubernetes API Server
                               │
                               │
                      Resource Watch Events
                               │
                               ▼
                     Kubernetes Operator
                          (Kopf)
                               │
                               ▼
                     Dirty Namespace Queue
                               │
                               ▼
                     Security Manager
                               │
      ┌──────────┬──────────┬──────────┬──────────┐
      ▼          ▼          ▼          ▼          ▼
 Namespace     Pod      Deployment   Network    RBAC
 Scanner      Scanner    Scanner     Scanner   Scanner
      │
      ▼
 Security Findings
      │
      ▼
 Namespace Security Report
      │
      ▼
 Security Remediation
```

---

# Operator Workflow

The operator itself contains **no security logic**.

Its only responsibilities are

- Watch Kubernetes resources
- Detect changes
- Mark namespaces dirty
- Queue reconciliation
- Invoke SecurityManager

Workflow:

```
Watch Resource

      │

      ▼

Mark Namespace Dirty

      │

      ▼

Worker Queue

      │

      ▼

SecurityManager

      │

      ▼

Scanners

      │

      ▼

Findings

      │

      ▼

Namespace Report
```

---

# Dirty Namespace Queue

One of the biggest improvements over the initial implementation was introducing a **dirty namespace queue**.

Instead of reconciling immediately for every Kubernetes event, the operator:

1. Receives an event
2. Marks the namespace dirty
3. Adds it to the queue
4. A background worker reconciles namespaces sequentially

Benefits:

- prevents duplicate reconciliations
- avoids API storms
- avoids repeated rescans
- improves scalability
- simplifies retry handling

---

# Security Manager

The SecurityManager orchestrates the entire reconciliation process.

Responsibilities include:

- Load SecurityPolicyProfile
- Execute all scanners
- Merge findings
- Deduplicate findings
- Update SecurityFinding CRDs
- Resolve obsolete findings
- Update NamespaceSecurityReport
- Generate SecurityRemediation CRDs

The SecurityManager is intentionally the only component responsible for namespace reconciliation.

---

# Scanners

## Namespace Scanner

Checks namespace-wide security configuration.

Examples

- Pod Security Admission labels
- Missing namespace protections

---

## Pod Scanner

Scans standalone Pods.

Checks include

- Privileged containers
- hostNetwork
- hostPID
- hostPath
- runAsNonRoot
- Default ServiceAccount
- Resource limits
- Resource requests
- Liveness probe
- Readiness probe
- Latest image tag

---

## Deployment Scanner

Deployment security is evaluated using the Pod template.

Instead of scanning every Pod created by a Deployment,

```
Deployment
     │
     ▼
spec.template
     │
     ▼
Reuse PodScanner
```

This avoids duplicate logic and unnecessary API calls.

---

## StatefulSet Scanner

Uses the same Pod template approach.

Checks

- ServiceAccount
- Privileged containers
- hostPath
- runAsNonRoot
- Resource configuration

---

## DaemonSet Scanner

Checks

- Privileged containers
- hostPID
- hostNetwork
- hostPath
- ServiceAccount
- runAsNonRoot

---

## Job Scanner

Checks

- Default ServiceAccount
- runAsNonRoot
- SecurityContext

Completed Jobs remain represented by findings until the Job is removed or updated.

---

## Network Scanner

Checks

- Missing NetworkPolicy
- LoadBalancer exposure
- NodePort exposure

Future

- NetworkPolicy completeness
- Default deny verification
- Cilium policy analysis

---

## RBAC Scanner

Current checks

- Default ServiceAccount usage

Future

- ClusterRoleBindings
- cluster-admin detection
- Wildcard permissions

---

# Finding Lifecycle

Every finding follows the same lifecycle.

```
Resource Created

        │

        ▼

Finding Created

        │

        ▼

Active

        │

Resource Fixed

        │

        ▼

Resolved

        │

Resource Deleted

        │

        ▼

Removed from scoring
```

The operator **never deletes findings immediately**.

Instead it changes

```
status.state

Active
↓

Resolved
```

This preserves historical evidence while allowing the namespace score to reflect only current issues.

---

# Active vs Resolved Findings

NamespaceSecurityReport is calculated **only from Active findings**.

Resolved findings remain available for auditing but do not affect:

- Score
- Posture
- Active finding count

---

# Namespace Security Score

Current scoring model

```
Score starts at 100

Critical  → -30

High      → -15

Medium    → -6

Low       → -2
```

Only Active findings are considered.

Posture

| Score | Posture |
|--------|----------|
| 85-100 | Healthy |
| 70-84 | Moderate |
| 40-69 | Risky |
| 0-39 | Critical |

---

# Supported Security Findings

Current coverage includes

✅ Privileged containers

✅ hostNetwork

✅ hostPID

✅ hostPath

✅ runAsNonRoot

✅ Default ServiceAccount

✅ Missing NetworkPolicy

✅ LoadBalancer exposure

✅ NodePort exposure

✅ Missing Pod Security Admission

---

# CRDs

## SecurityPolicyProfile

Defines security requirements.

Example

```yaml
rules:
  requireRunAsNonRoot: true
  forbidPrivilegedContainers: true
  requireDedicatedServiceAccount: true
```

---

## SecurityFinding

Represents one detected issue.

Contains

- Severity
- Category
- Resource
- Recommendation
- State

---

## NamespaceSecurityReport

Aggregates namespace security.

Contains

- Score
- Posture
- Active Findings
- Unique Findings
- Timestamp

---

## SecurityRemediation

Provides suggested fixes.

Example

```
Use dedicated ServiceAccount

Set runAsNonRoot=true

Create NetworkPolicy
```

---

# Scalability Features

Implemented

- Event-driven reconciliation
- Dirty namespace queue
- Incremental reconciliation
- Finding deduplication
- Deployment template scanning
- Active/Resolved lifecycle
- Namespace aggregation

Future improvements

- Shared Informers
- Kubernetes work queues
- Parallel reconciliation workers
- Informer cache
- API batching
- Prometheus metrics

---

# Testing

A dedicated namespace can be used for validation.

```
security-operator-demo
```

Suggested tests

- Privileged Pod
- Secure Pod
- Deployment
- DaemonSet
- StatefulSet
- Job
- NodePort Service
- LoadBalancer Service
- Missing NetworkPolicy
- Dedicated ServiceAccount
- Pod Security Admission labels

Expected behaviour

1. Create insecure resource
2. Operator detects issue
3. SecurityFinding becomes Active
4. NSR score decreases
5. Fix resource
6. Finding becomes Resolved
7. NSR score increases automatically

---

# Deployment

The operator currently supports

- Local development
- Helm deployment

Future production deployment will package

- CRDs
- RBAC
- ServiceAccount
- Deployment
- ConfigMap
- Values
- SecurityPolicyProfile

into a single Helm chart.

---

# Project Structure

```
k8s-security-operator/
│
├── app/
│   ├── operator.py
│   ├── security_manager.py
│   ├── models.py
│   ├── scoring.py
│   ├── utils.py
│   │
│   ├── scanners/
│   │     ├── namespace_scanner.py
│   │     ├── pod_scanner.py
│   │     ├── deployment_scanner.py
│   │     ├── statefulset_scanner.py
│   │     ├── daemonset_scanner.py
│   │     ├── job_scanner.py
│   │     ├── network_scanner.py
│   │     └── rbac_scanner.py
│
├── charts/
│
├── Dockerfile
│
├── requirements.txt
│
└── README.md
```

---

# Current Limitations

- Operator restart is required after code changes.
- Completed Jobs may remain until deleted.
- Network security currently checks exposure rather than traffic behaviour.
- Runtime threat detection is outside the current scope.
- Image vulnerability scanning is planned but not yet integrated.

---

# Future Roadmap

- Helm-based production deployment
- Trivy integration
- Kubescape integration
- Falco runtime events
- Prometheus metrics
- Grafana dashboards
- Admission webhook
- Incremental scoring
- Multi-worker reconciliation
- Secret scanning
- RBAC privilege analysis
- CVE enrichment
- Security trend history

---

# Design Principles

This operator follows several core Kubernetes design patterns:

- Kubernetes Controller Pattern
- Reconciliation Loop
- Event-Driven Processing
- Single Responsibility Principle
- Kubernetes-native persistence using CRDs
- Idempotent reconciliation
- Namespace-level aggregation
- Incremental state updates

The result is a modular, extensible, and scalable security platform capable of continuously assessing Kubernetes namespace security posture while minimizing API server load and operational overhead.