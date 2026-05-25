#!/usr/bin/env bash
# Wait for the Wazuh dashboard Service to have ready endpoints, then exec
# kubectl port-forward bound to 0.0.0.0 (so IAP tunnel can reach the listener
# via the VM's nic0, not just loopback).
#
# Designed to be run by systemd with Restart=always. Returns 0 only when
# kubectl exits cleanly; any failure → systemd restarts → wait loop repeats.
set -euo pipefail

KUBECONFIG="${KUBECONFIG:-/home/n3m0/.kube/config}"
NAMESPACE="${NAMESPACE:-wazuh}"
SERVICE="${SERVICE:-dashboard}"
LOCAL_PORT="${LOCAL_PORT:-8443}"
TARGET_PORT="${TARGET_PORT:-443}"
ADDRESS="${ADDRESS:-0.0.0.0}"

export KUBECONFIG

log() { echo "[$(date +%H:%M:%S)] $*"; }

# 1) kubectl reachable + cluster up?
until kubectl version --request-timeout=3s >/dev/null 2>&1; do
  log "waiting for kube-apiserver..."
  sleep 5
done

# 2) Service exists?
until kubectl get svc "$SERVICE" -n "$NAMESPACE" >/dev/null 2>&1; do
  log "waiting for svc/$SERVICE in $NAMESPACE..."
  sleep 5
done

# 3) Has at least one ready endpoint?
until [ -n "$(kubectl get endpoints "$SERVICE" -n "$NAMESPACE" -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null)" ]; do
  log "waiting for endpoints on svc/$SERVICE..."
  sleep 5
done

log "svc/$SERVICE ready; starting port-forward on $ADDRESS:$LOCAL_PORT → $SERVICE:$TARGET_PORT"
exec kubectl port-forward "svc/$SERVICE" -n "$NAMESPACE" \
  "$LOCAL_PORT:$TARGET_PORT" --address="$ADDRESS"
