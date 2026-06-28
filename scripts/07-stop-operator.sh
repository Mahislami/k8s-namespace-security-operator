#!/usr/bin/env bash
set -euo pipefail

NS="${1:-security-operator-demo}"

kubectl scale deployment namespace-security-operator -n "$NS" --replicas=0
