#!/usr/bin/env bash
set -euo pipefail

NS="${1:-security-operator-demo}"

kubectl delete configmap risky-config -n "$NS" --ignore-not-found
kubectl delete secret risky-secret -n "$NS" --ignore-not-found
kubectl delete pvc risky-pvc -n "$NS" --ignore-not-found
kubectl delete svc risky-nodeport-service -n "$NS" --ignore-not-found
kubectl delete deployment risky-deployment -n "$NS" --ignore-not-found
kubectl delete daemonset risky-daemonset -n "$NS" --ignore-not-found
kubectl delete job risky-job -n "$NS" --ignore-not-found
kubectl delete pod risky-standalone-pod -n "$NS" --ignore-not-found
kubectl delete pod -n "$NS" -l job-name=risky-job --ignore-not-found

kubectl delete sf -n "$NS" --all --ignore-not-found
kubectl delete sr -n "$NS" --all --ignore-not-found
kubectl delete nsr -n "$NS" --all --ignore-not-found

echo "Cleaned test resources in $NS without deleting the namespace/operator."
