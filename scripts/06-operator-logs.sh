#!/usr/bin/env bash
set -euo pipefail

NS="${1:-security-operator-demo}"

kubectl logs -n "$NS" deployment/namespace-security-operator -f --tail=150
