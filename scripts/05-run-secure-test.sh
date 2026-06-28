#!/usr/bin/env bash
set -euo pipefail

NS="${1:-security-operator-demo}"

kubectl delete pod risky-standalone-pod -n "$NS" --ignore-not-found
kubectl delete job risky-job -n "$NS" --ignore-not-found
kubectl delete pod -n "$NS" -l job-name=risky-job --ignore-not-found
kubectl delete pvc risky-pvc -n "$NS" --ignore-not-found

kubectl apply -f ../examples/comprehensive-secure-test.yaml

kubectl rollout restart deployment risky-deployment -n "$NS" || true
kubectl rollout restart daemonset risky-daemonset -n "$NS" || true

echo "Waiting for secure rollout and reconciliation..."
sleep 20

kubectl get nsr -n "$NS"
echo
echo "ACTIVE findings:"
kubectl get sf -n "$NS" -l security.meslami.io/state=active || true
echo
echo "RESOLVED findings:"
kubectl get sf -n "$NS" -l security.meslami.io/state=resolved || true
echo
echo "RESOLVED remediations:"
kubectl get sr -n "$NS" -l security.meslami.io/state=resolved || true
