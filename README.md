# Kubernetes Namespace Security Operator

A Kubernetes-native Security Operator built with Python and Kopf that continuously monitors namespace security posture, detects misconfigurations, generates findings, recommends remediations, and maintains namespace-level security reports.

---

## Features

### Security Monitoring

- Namespace Security Assessment
- Pod Security Assessment
- Deployment Security Assessment
- RBAC Security Assessment
- Network Security Assessment
- Cilium Network Policy Assessment

### Findings & Reporting

- SecurityFinding CRDs
- SecurityRemediation CRDs
- NamespaceSecurityReport CRDs
- Security scoring and posture classification

### Scalability

- Event-driven architecture
- Deployment template scanning
- Paginated reconciliation
- Namespace-level aggregation
- Minimal API server load

### Extensibility

Future integrations:

- Trivy
- Kubescape
- Falco
- Prometheus
- Grafana

---

# Architecture

```text
                    Kubernetes Cluster
                             │
                             ▼

                    Security Operator
                             │
                             ▼

                     SecurityManager
                             │
         ┌───────────┬───────────┬───────────┐
         ▼           ▼           ▼           ▼

 Namespace     PodScanner   Deployment   Network
 Scanner                     Scanner     Scanner
                                            │
                                            ▼
                                      RBACScanner

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

# Core Components

## Operator

The Operator is responsible for watching Kubernetes resources and reacting to changes.

Monitored resources:

- Namespaces
- Pods
- Deployments
- ServiceAccounts
- RoleBindings
- NetworkPolicies
- CiliumNetworkPolicies

The Operator itself contains no security logic.

Its responsibility is:

```text
Watch
  →
Delegate
  →
Reconcile
```

---

## SecurityManager

The SecurityManager orchestrates all security evaluation activities.

Responsibilities:

- Load SecurityPolicyProfile
- Execute scanners
- Aggregate findings
- Create reports
- Create remediation suggestions

---

## NamespaceScanner

Checks namespace-level security posture.

Examples:

- Pod Security Admission labels
- Namespace security settings

---

## PodScanner

Evaluates workload-level security.

Checks include:

- Privileged containers
- hostNetwork
- hostPID
- hostPath
- runAsNonRoot
- Latest image tags
- Default ServiceAccount
- Resource limits
- Resource requests
- Probes

---

## DeploymentScanner

Evaluates:

- Replica count
- Update strategy
- Deployment Pod Template security

The DeploymentScanner reuses PodScanner logic to avoid code duplication.

---

## NetworkScanner

Evaluates:

- NetworkPolicy presence
- Default isolation
- CiliumNetworkPolicy presence

---

## RBACScanner

Evaluates:

- cluster-admin RoleBindings
- Default ServiceAccount permissions
- Namespace RBAC posture

---

# Event-Driven Design

The operator avoids expensive cluster-wide rescans.

### Pod Event

```text
Pod Created
     │
     ▼
Scan only that Pod
```

### Deployment Event

```text
Deployment Updated
        │
        ▼
Scan only Deployment Template
```

### NetworkPolicy Event

```text
NetworkPolicy Updated
          │
          ▼
Namespace Reconciliation
```

---

# Security CRDs

## SecurityPolicyProfile

Defines desired security posture.

Example:

```yaml
rules:
  forbidPrivilegedContainers: true
  requireRunAsNonRoot: true
  requireNetworkPolicy: true
```

---

## SecurityFinding

Represents a detected security issue.

Example:

```yaml
kind: SecurityFinding

spec:
  severity: high
  category: pod-security
  issue: Pod uses hostNetwork
```

---

## SecurityRemediation

Represents a recommended fix.

Example:

```yaml
kind: SecurityRemediation

spec:
  actionType: manifest-patch
  description: Disable hostNetwork
```

---

## NamespaceSecurityReport

Aggregated namespace posture.

Example:

```yaml
status:
  score: 82
  posture: Moderate
```

---

# Security Coverage

| Area | Coverage |
|--------|-----------|
| Namespace Security | ✅ |
| Pod Security | ✅ |
| Deployment Security | ✅ |
| Network Policies | ✅ |
| Cilium Policies | ✅ |
| RBAC Security | ✅ |
| Service Accounts | ✅ |
| Resource Controls | ✅ |
| Runtime Security | Planned |
| Image Vulnerabilities | Planned |

---

# Repository Structure

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
│       ├── network_scanner.py
│       └── rbac_scanner.py
│
├── charts/
│   └── namespace-security-operator/
│       ├── Chart.yaml
│       ├── values.yaml
│       ├── crds/
│       └── templates/
│
├── Dockerfile
├── requirements.txt
└── README.md
```

---

# Scalability Considerations

The design focuses on large-scale Kubernetes environments.

Implemented:

- Event-driven scanning
- Deployment template scanning
- Paginated Pod listing
- Namespace-level aggregation
- Periodic reconciliation

Future improvements:

- Shared informer cache
- Work queues
- Parallel processing
- Distributed scanning
- Incremental report updates

---

# Future Roadmap

### Security Integrations

- Trivy
- Kubescape
- Falco

### Observability

- Prometheus metrics
- Grafana dashboards

### Advanced Security

- Secret scanning
- Node security scanning
- Runtime anomaly detection
- Admission control integration

---

# Design Philosophy

This project follows:

- Kubernetes Controller Pattern
- Event-Driven Architecture
- Reconciliation Pattern
- Single Responsibility Principle
- Kubernetes-Native Persistence using CRDs

The result is a modular, extensible, and scalable security platform designed to continuously evaluate Kubernetes namespace security posture while minimizing operational overhead.