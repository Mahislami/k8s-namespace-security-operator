#!/usr/bin/env bash
set -euo pipefail

NS="${1:-security-operator-demo}"

if ! kubectl get ns "$NS" >/dev/null 2>&1; then
  echo "Namespace $NS does not exist."
  exit 0
fi

PHASE="$(kubectl get ns "$NS" -o jsonpath='{.status.phase}')"

if [ "$PHASE" != "Terminating" ]; then
  echo "Namespace $NS exists and is not terminating."
  exit 0
fi

echo "Namespace $NS is stuck Terminating. Removing metadata.finalizers..."

kubectl patch namespace "$NS" \
  --type=json \
  -p='[{"op":"remove","path":"/metadata/finalizers"}]' || true

echo "Waiting for namespace $NS to disappear..."
until ! kubectl get ns "$NS" >/dev/null 2>&1; do
  sleep 2
done

echo "Namespace $NS removed."
