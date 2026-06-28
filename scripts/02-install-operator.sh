#!/usr/bin/env bash
set -euo pipefail

NS="${1:-security-operator-demo}"
WATCH_NAMESPACES=""

./scripts/01-create-namespace.sh "$NS"

helm upgrade --install namespace-security-operator \
  charts/namespace-security-operator \
  -n "$NS" \
  --create-namespace \
  --set image.repository="mahdislami/namespace-security-operator" \
  --set image.tag="latest" \
  --set image.pullPolicy="Always" \
  --set operator.namespace="$NS" \
  --set operator.watchNamespaces="$WATCH_NAMESPACES" \
  --set operator.resolvedFindingRetentionDays="30"

kubectl rollout status deployment/namespace-security-operator -n "$NS"

echo "Operator installed in $NS"
