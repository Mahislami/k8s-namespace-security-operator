#!/usr/bin/env bash
set -euo pipefail

NS="${1:-security-operator-demo}"

kubectl apply -f comprehensive-insecure-test.yaml

echo "Waiting for operator reconciliation..."
sleep 35

kubectl get nsr -n "$NS"
echo
kubectl get sf -n "$NS" -l security.meslami.io/state=active
echo
kubectl get sr -n "$NS" -l security.meslami.io/state=active
