#!/usr/bin/env bash
set -euo pipefail

NS="${1:-security-operator-demo}"

./scripts/00-unblock-namespace-if-terminating.sh "$NS"

kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -

echo "Namespace ready: $NS"
