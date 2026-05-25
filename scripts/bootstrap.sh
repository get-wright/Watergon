#!/usr/bin/env bash
# Watergon thin bootstrap. Runs on the Packer-baked VM as the GCE
# metadata_startup_script. Idempotent — safe to re-run.
#
# Assumes Docker, kubectl, kind, helm, k9s are already installed (baked).
# Provisions: kind cluster → manifests → wazuh-server → wazuh-agent.
set -euo pipefail

REPO_DIR="${REPO_DIR:-/opt/watergon}"
WAZUH_DIR="${WAZUH_DIR:-/opt/wazuh-kubernetes}"
WAZUH_REF="${WAZUH_REF:-v4.14.1}"
KIND_CLUSTER="${KIND_CLUSTER:-security-lab}"
AGENT_IMAGE="${AGENT_IMAGE:-wazuh-agent-local:4.14.1}"
LOG="/var/log/watergon-bootstrap.log"

# Tee everything to a log (for `gcloud compute instances tail-serial-port-output`
# or post-mortem inspection).
exec > >(tee -a "$LOG") 2>&1

phase() { echo -e "\n========== [$(date +%H:%M:%S)] $* ==========\n"; }

# -----------------------------------------------------------------
# Bootstrap requires the repo on disk. Fetch on first run if not yet
# present. After that, this script + repo are managed by whoever
# updates /opt/watergon (e.g. gcloud compute scp, a CI job, or git pull).
# -----------------------------------------------------------------
if [ ! -d "$REPO_DIR" ]; then
  phase "Repo not found at $REPO_DIR — set REPO_DIR or scp the repo first"
  echo "Run from your laptop:"
  echo "  gcloud compute scp --recurse ~/Code/Watergon <vm>:/tmp/Watergon --zone=... --project=..."
  echo "  gcloud compute ssh <vm> -- sudo mv /tmp/Watergon /opt/watergon"
  echo "Then re-run: sudo bash /opt/watergon/scripts/bootstrap.sh"
  exit 1
fi

cd "$REPO_DIR"

phase "PHASE 1 — kind cluster"
if ! kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER"; then
  mkdir -p /tmp/kind-security-lab
  kind create cluster --config cluster/kind-config.yaml
fi
# inside-node sysctl (kind nodes are containers; vm.max_map_count is per-netns... actually per-host kernel, set once on host).
for node in $(kubectl get nodes -o name | sed 's|node/||'); do
  docker exec "$node" sysctl -w vm.max_map_count=262144 >/dev/null 2>&1 || true
done

phase "PHASE 2 — namespaces + RBAC"
kubectl apply -k manifests/namespaces

phase "PHASE 3 — metrics-server"
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
kubectl patch deployment metrics-server -n kube-system --type='json' \
  -p='[{"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--kubelet-insecure-tls"}]' \
  2>/dev/null || true

phase "PHASE 4 — Tetragon (helm + extras)"
helm repo add cilium https://helm.cilium.io 2>/dev/null || true
helm repo update
if ! helm status tetragon -n kube-system >/dev/null 2>&1; then
  helm install tetragon cilium/tetragon -n kube-system -f manifests/tetragon/values.yaml
else
  helm upgrade tetragon cilium/tetragon -n kube-system -f manifests/tetragon/values.yaml
fi
kubectl rollout status -n kube-system ds/tetragon --timeout=300s
# TracingPolicy CRDs are namespaced under vulnerable-apps; ns must exist (does via Phase 2).
kubectl apply -k manifests/tetragon

phase "PHASE 5 — Wazuh server (upstream wazuh-kubernetes + overrides)"
if [ ! -d "$WAZUH_DIR" ]; then
  git clone --depth=1 -b "$WAZUH_REF" https://github.com/wazuh/wazuh-kubernetes.git "$WAZUH_DIR"
fi

# Generate self-signed certs (idempotent — re-runs are safe)
chmod +x "$WAZUH_DIR/wazuh/certs/indexer_cluster/generate_certs.sh" \
         "$WAZUH_DIR/wazuh/certs/dashboard_http/generate_certs.sh"
[ -f "$WAZUH_DIR/wazuh/certs/indexer_cluster/root-ca.pem" ] || \
  bash "$WAZUH_DIR/wazuh/certs/indexer_cluster/generate_certs.sh"
[ -f "$WAZUH_DIR/wazuh/certs/dashboard_http/cert.pem" ] || \
  bash "$WAZUH_DIR/wazuh/certs/dashboard_http/generate_certs.sh"

# Apply local overrides into the cloned tree.
cp manifests/wazuh-server/overrides/base-storage-class.yaml       "$WAZUH_DIR/wazuh/base/storage-class.yaml"
cp manifests/wazuh-server/overrides/local-env-storage-class.yaml  "$WAZUH_DIR/envs/local-env/storage-class.yaml"
cp manifests/wazuh-server/overrides/services-clusterip-patch.yaml "$WAZUH_DIR/envs/local-env/services-clusterip-patch.yaml"
cp manifests/wazuh-server/overrides/kustomization.yml             "$WAZUH_DIR/envs/local-env/kustomization.yml"

# Bump manager resources (default 400m / 512Mi is too low).
sed -i 's/cpu: 400m/cpu: "2"/; s/memory: 512Mi/memory: 2Gi/' "$WAZUH_DIR/wazuh/wazuh_managers/wazuh-master-sts.yaml"
sed -i 's/cpu: 400m/cpu: "2"/; s/memory: 512Mi/memory: 2Gi/' "$WAZUH_DIR/wazuh/wazuh_managers/wazuh-worker-sts.yaml"

kubectl apply -k "$WAZUH_DIR/envs/local-env/"

phase "PHASE 6 — wait for Wazuh pods"
kubectl rollout status statefulset/wazuh-indexer        -n wazuh --timeout=900s
kubectl rollout status statefulset/wazuh-manager-master -n wazuh --timeout=600s
kubectl rollout status statefulset/wazuh-manager-worker -n wazuh --timeout=600s
kubectl rollout status deployment/wazuh-dashboard       -n wazuh --timeout=600s

phase "PHASE 7 — extras"
kubectl apply -k manifests/wazuh-server/extras

phase "PHASE 8 — build + load wazuh-agent image into kind"
AGENT_BUILD_DIR="${REPO_DIR}/manifests/wazuh-agent/agent-image"
if ! docker image inspect "$AGENT_IMAGE" >/dev/null 2>&1; then
  docker build -t "$AGENT_IMAGE" "$AGENT_BUILD_DIR"
fi
kind load docker-image "$AGENT_IMAGE" --name "$KIND_CLUSTER"

phase "PHASE 9 — wazuh-agent (rules CM + sync Job + DS)"
kubectl apply -k manifests/wazuh-agent

# Wait for rules-sync Job to finish before checking DS rollout — agents
# need the k8s-nodes group to enroll, which the Job creates.
kubectl wait --for=condition=complete --timeout=600s job/wazuh-rules-sync -n wazuh

phase "PHASE 10 — workloads"
kubectl apply -k manifests/workloads

phase "PHASE 11 — wait for DS"
kubectl rollout status ds/wazuh-agent -n wazuh --timeout=300s

phase "PHASE 12 — install systemd unit for dashboard port-forward"
# Makes svc/dashboard reachable via IAP tunnel on port 8443, auto-restarted by systemd.
# The wrapper script waits for the service to become ready before binding.
install -o root -g root -m 0755 "${REPO_DIR}/scripts/systemd/watergon-dashboard-pf.sh" /usr/local/bin/watergon-dashboard-pf.sh
install -o root -g root -m 0644 "${REPO_DIR}/scripts/systemd/watergon-dashboard-pf.service" /etc/systemd/system/watergon-dashboard-pf.service
# If user differs from "n3m0" (the default in the unit), patch it in-place.
RUN_USER="${SUDO_USER:-${USER:-n3m0}}"
if [ "$RUN_USER" != "n3m0" ]; then
  sed -i "s|^User=n3m0|User=${RUN_USER}|; s|^Group=n3m0|Group=${RUN_USER}|; s|/home/n3m0/|/home/${RUN_USER}/|g" \
    /etc/systemd/system/watergon-dashboard-pf.service
fi
systemctl daemon-reload
systemctl enable --now watergon-dashboard-pf.service

phase "DONE"
kubectl get pods -A
echo
kubectl exec -n wazuh wazuh-manager-master-0 -- /var/ossec/bin/manage_agents -l 2>/dev/null || true
