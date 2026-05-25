# Tetragon and Wazuh 

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                      kind cluster: security-lab                      │
│                                                                      │
│  kube-system            wazuh                                        │
│  ┌──────────────┐    ┌───────────────────────────────────────────┐   │
│  │   Tetragon   │    │  wazuh-manager-master  (StatefulSet)      │   │
│  │  (DaemonSet) │    │  wazuh-manager-worker  (StatefulSet)      │   │
│  │  eBPF hooks  │    │  wazuh-indexer         (StatefulSet)      │   │
│  └──────┬───────┘    │  wazuh-dashboard       (Deployment)       │   │
│         │            │  wazuh-agent            (DaemonSet)       │   │
│         │            └──────────────────────────┬────────────────┘   │
│         │  writes to       ▲  alerts via ossec  │                    │
│         │  host path       └────────────────────┘                    │
│         └─► /var/run/cilium/tetragon/tetragon.log (JSON)             │
│             ↑ mounted read-only into each wazuh-agent pod            │
│                                                                      │
│  vulnerable-apps         security-testing         monitoring         │
│  ┌──────────────────┐   ┌───────────────────┐   ┌──────────────┐     │
│  │ test-shell       │   │ security-test-sa  │   │ (reserved)   │     │
│  │ test-nginx       │   └───────────────────┘   └──────────────┘     │
│  │ test-privileged  │                                                │
│  │ test-network     │                                                │
│  │ vulnerable-webapp│                                                │
│  └──────────────────┘                                                │
└──────────────────────────────────────────────────────────────────────┘
```

**Data flow:**
1. Tetragon hooks into the Linux kernel via eBPF on each node, writing JSON events to `/var/run/cilium/tetragon/tetragon.log` on the host filesystem
2. Wazuh agent DaemonSet (in the `wazuh` namespace) mounts that host path at `/host/var/run/cilium/tetragon/tetragon.log` and reads it as a JSON `localfile` source
3. Wazuh agent forwards decoded events to the Wazuh manager worker over port 1514
4. Wazuh manager fires custom detection rules and Active Response actions, storing alerts in the Wazuh indexer
5. Wazuh dashboard provides a UI for alert triage, rule management, and agent oversight

---

## Part A — Infrastructure Setup

---

## Step 1 — Install Docker

```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
newgrp docker
rm get-docker.sh
```

Verify:
```bash
docker ps
```

---

## Step 2 — Install kubectl

```bash
curl -LO "https://dl.k8s.io/release/$(curl -Ls https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
rm kubectl
```

Verify:
```bash
kubectl version --client
```

---

## Step 3 — Install kind

```bash
[ $(uname -m) = x86_64 ] && curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.31.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind
kind --version
```

---

## Step 4 — Install Helm

```bash
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
helm version
```

---

## Step 5 — Install k9s (optional TUI)

```bash
wget https://github.com/derailed/k9s/releases/latest/download/k9s_linux_amd64.deb
sudo apt install ./k9s_linux_amd64.deb
rm k9s_linux_amd64.deb
```

---

## Step 6 — Create the Kind Cluster

Create the required host directory first:
```bash
mkdir -p /tmp/kind-security-lab
mkdir -p ~/K8s && cd ~/K8s
```

Create the cluster config:

```bash
cat <<EOF > kind-security-cluster.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: security-lab
nodes:
  - role: control-plane
    kubeadmConfigPatches:
    - |
      kind: InitConfiguration
      nodeRegistration:
        kubeletExtraArgs:
          node-labels: "node-type=control-plane"
    extraMounts:
      - hostPath: /tmp/kind-security-lab
        containerPath: /host-data
      - hostPath: /lib/modules
        containerPath: /lib/modules
        readOnly: true
      - hostPath: /usr/src
        containerPath: /usr/src
        readOnly: true
    extraPortMappings:
      - containerPort: 30000
        hostPort: 30000
        protocol: TCP
      - containerPort: 30001
        hostPort: 30001
        protocol: TCP
  - role: worker
    kubeadmConfigPatches:
    - |
      kind: JoinConfiguration
      nodeRegistration:
        kubeletExtraArgs:
          node-labels: "node-type=worker,workload=security-test"
    extraMounts:
      - hostPath: /tmp/kind-security-lab
        containerPath: /host-data
      - hostPath: /lib/modules
        containerPath: /lib/modules
        readOnly: true
      - hostPath: /usr/src
        containerPath: /usr/src
        readOnly: true
  - role: worker
    kubeadmConfigPatches:
    - |
      kind: JoinConfiguration
      nodeRegistration:
        kubeletExtraArgs:
          node-labels: "node-type=worker,workload=security-test"
    extraMounts:
      - hostPath: /tmp/kind-security-lab
        containerPath: /host-data
      - hostPath: /lib/modules
        containerPath: /lib/modules
        readOnly: true
      - hostPath: /usr/src
        containerPath: /usr/src
        readOnly: true
featureGates:
  "ProcMountType": true
networking:
  disableDefaultCNI: false
  podSubnet: "10.244.0.0/16"
  serviceSubnet: "10.96.0.0/12"
EOF
```

Create the cluster:
```bash
kind create cluster --config kind-security-cluster.yaml
```

Verify:
```bash
kubectl cluster-info --context kind-security-lab
kubectl get nodes
```

### 6.1 — Raise inotify limits for Wazuh

Wazuh's `wazuh-modulesd` daemon uses inotify watches internally. The default Linux limits are too low for a cluster running Kubernetes controllers + Tetragon + Wazuh simultaneously. Without this fix, `wazuh-modulesd` will crash with `CRITICAL: Couldn't init inotify: Too many open files`, causing the dashboard to show `ERROR3099 - Wazuh not ready yet`.

Set the limits on the **host machine** (kind nodes share the host kernel):

```bash
sudo sysctl -w fs.inotify.max_user_watches=524288
sudo sysctl -w fs.inotify.max_user_instances=512
```

Make permanent across reboots:
```bash
echo "fs.inotify.max_user_watches=524288" | sudo tee -a /etc/sysctl.conf
echo "fs.inotify.max_user_instances=512" | sudo tee -a /etc/sysctl.conf
```

> **Why here and not later?** These limits must be in place before Wazuh starts. If the cluster is already running and Wazuh is deployed, restart the manager after applying: `kubectl exec -it wazuh-manager-master-0 -n wazuh -- /var/ossec/bin/wazuh-control restart`

---

## Step 7 — Set Up Namespaces and RBAC

```bash
kubectl create namespace vulnerable-apps
kubectl create namespace security-testing
kubectl create namespace monitoring

kubectl label namespace vulnerable-apps env=test security=monitored
kubectl label namespace security-testing env=test security=monitored

# Service account for testing
kubectl create serviceaccount security-test-sa -n security-testing

cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: security-test-role
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["configmaps", "secrets"]
    verbs: ["get", "list"]
EOF

kubectl create clusterrolebinding security-test-binding \
  --clusterrole=security-test-role \
  --serviceaccount=security-testing:security-test-sa
```

---

## Step 8 — Install Metrics Server

```bash
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml

# Required patch for kind (skip TLS verification against kubelets)
kubectl patch deployment metrics-server -n kube-system --type='json' \
  -p='[{"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--kubelet-insecure-tls"}]'
```

---

## Step 9 — Deploy Test Workloads

### Shell pod

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-shell
  namespace: vulnerable-apps
  labels:
    app: test-shell
    security: monitored
spec:
  containers:
  - name: shell
    image: ubuntu:22.04
    command: ["/bin/sleep", "infinity"]
    securityContext:
      runAsNonRoot: false
      privileged: false
    volumeMounts:
    - name: host-data
      mountPath: /host-data
  volumes:
  - name: host-data
    hostPath:
      path: /tmp
      type: Directory
EOF
```

### Nginx pod with sensitive ConfigMap

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: sensitive-config
  namespace: vulnerable-apps
data:
  secret.txt: |
    This is sensitive data
    Database password: P@ssw0rd123
---
apiVersion: v1
kind: Pod
metadata:
  name: test-nginx
  namespace: vulnerable-apps
  labels:
    app: nginx
    security: monitored
spec:
  containers:
  - name: nginx
    image: nginx:latest
    ports:
    - containerPort: 80
    volumeMounts:
    - name: sensitive-data
      mountPath: /etc/sensitive
      readOnly: true
    - name: etc-volume
      mountPath: /host-etc
      readOnly: true
  volumes:
  - name: sensitive-data
    configMap:
      name: sensitive-config
  - name: etc-volume
    hostPath:
      path: /etc
      type: Directory
EOF
```

### Privileged pod

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-privileged
  namespace: vulnerable-apps
  labels:
    app: privileged-test
    security: monitored
spec:
  containers:
  - name: privileged-container
    image: busybox
    command: ["/bin/sh", "-c", "sleep infinity"]
    securityContext:
      privileged: true
      capabilities:
        add:
        - SYS_ADMIN
        - NET_ADMIN
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
      type: Directory
EOF
```

### Network tools pod

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-network
  namespace: vulnerable-apps
  labels:
    app: network-test
    security: monitored
spec:
  containers:
  - name: network-tools
    image: nicolaka/netshoot
    command: ["/bin/sleep", "infinity"]
EOF
```

### Vulnerable web app (DVWA)

```bash
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-webapp
  namespace: vulnerable-apps
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vulnerable-webapp
  template:
    metadata:
      labels:
        app: vulnerable-webapp
        security: monitored
    spec:
      containers:
      - name: webapp
        image: vulnerables/web-dvwa
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: vulnerable-webapp-svc
  namespace: vulnerable-apps
spec:
  type: NodePort
  ports:
  - port: 80
    targetPort: 80
    nodePort: 30000
  selector:
    app: vulnerable-webapp
EOF
```

### Secrets and ConfigMaps

```bash
kubectl create secret generic db-credentials \
  --from-literal=username=admin \
  --from-literal=password=SuperSecret123 \
  -n vulnerable-apps

kubectl create configmap app-config \
  --from-literal=api_key=sk-1234567890abcdef \
  --from-literal=database_url=postgresql://admin:password@db:5432/appdb \
  -n vulnerable-apps
```

---

## Step 10 — Install Tetragon

```bash
helm repo add cilium https://helm.cilium.io
helm repo update
helm install tetragon cilium/tetragon -n kube-system
kubectl rollout status -n kube-system ds/tetragon -w
```

Verify Tetragon pods are running:
```bash
kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon
```

---

## Step 11 — Stream Tetragon Events

```bash
# Get any Tetragon pod
POD=$(kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon -o name | head -n1)

# Stream all security events from the vulnerable-apps namespace
kubectl exec -n kube-system ${POD} -c tetragon -- \
  tetra getevents -o compact --namespace vulnerable-apps
```

To watch events scoped to a specific pod's node:
```bash
TARGET_NODE=$(kubectl get pod <your-pod-name> -n vulnerable-apps -o jsonpath='{.spec.nodeName}')

POD=$(kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon \
  -o name --field-selector spec.nodeName=${TARGET_NODE} | head -n1)

kubectl exec -n kube-system ${POD} -c tetragon -- \
  tetra getevents -o compact --namespace vulnerable-apps
```

---

## Step 12 — Trigger Test Events

In a separate terminal, exec into the test shell and run commands that Tetragon will detect:

```bash
kubectl exec -it test-shell -n vulnerable-apps -- bash
```

Inside the pod:
```bash
cat /etc/shadow          # sensitive file read
curl https://google.com  # outbound network connection
ps aux                   # process enumeration
ls -la /host-data        # host filesystem access
```

Watch the Tetragon terminal — each of the above should produce a security event in the event stream.

---

## Part B — Wazuh SIEM Integration

> **Resource check before continuing:** The Wazuh stack (manager + indexer + dashboard + agents) requires at minimum **6 vCPU** and **8 GB RAM** available across the cluster. Run `kubectl top nodes` to check headroom. If the host is constrained, temporarily stop test workloads with `kubectl delete pod test-shell test-nginx test-network -n vulnerable-apps` and restore them after Wazuh is stable.

---

## Step 13 — Deploy Wazuh Server

Wazuh provides an official Kubernetes repo (`wazuh/wazuh-kubernetes`) with Kustomize overlays. The `local-env` overlay reduces resource requests to fit a lab environment.

### 13.1 — Clone the repo

```bash
cd ~/K8s
git clone https://github.com/wazuh/wazuh-kubernetes.git -b v4.14.1 --depth=1
cd wazuh-kubernetes
```

> **Note:** v4.14.1 is the latest stable tagged release (November 2025). The `wazuh` namespace is created automatically by these manifests.

### 13.2 — Generate SSL certificates

Wazuh needs two sets of self-signed certificates: one for the OpenSearch indexer cluster, and one for the dashboard HTTPS endpoint.

```bash
# Indexer cluster certificates
chmod +x wazuh/certs/indexer_cluster/generate_certs.sh
bash wazuh/certs/indexer_cluster/generate_certs.sh

# Dashboard HTTPS certificate
chmod +x wazuh/certs/dashboard_http/generate_certs.sh
bash wazuh/certs/dashboard_http/generate_certs.sh
```

Verify certificates were created:
```bash
ls wazuh/certs/indexer_cluster/
# Expected: admin.pem  admin-key.pem  node.pem  node-key.pem  root-ca.pem

ls wazuh/certs/dashboard_http/
# Expected: cert.pem  key.pem
```

### 13.3 — Fix StorageClass provisioner for kind

The `wazuh-kubernetes` repo ships with the StorageClass provisioner commented out (or set to `microk8s.io/hostpath`). Kind uses `rancher.io/local-path` instead. The provisioner must be set **in the base file** — a Kustomize patch cannot add a field that is missing or commented out in the base.

First, confirm your cluster's provisioner:
```bash
kubectl get sc
# Expected output for kind:
# NAME                 PROVISIONER             ...
# standard (default)   rancher.io/local-path   ...
```

Edit the base StorageClass to set the correct provisioner:
```bash
cat <<'EOF' > wazuh/base/storage-class.yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: wazuh-storage
provisioner: rancher.io/local-path
reclaimPolicy: Delete
volumeBindingMode: WaitForFirstConsumer
EOF
```

> **Why edit the base instead of using a patch?** The upstream `storage-class.yaml` has the `provisioner` field commented out. Kustomize strategic merge patches can only override fields that already exist in the base manifest — they cannot add new fields. Editing the base directly is the only reliable fix.

### 13.4 — Patch services to ClusterIP for kind

By default `wazuh-kubernetes` creates `LoadBalancer` services. Kind has no cloud load-balancer controller, so those stay `<pending>` forever. Since everything runs inside the cluster, `ClusterIP` is correct for all services. Dashboard access uses `kubectl port-forward`.

```bash
cat <<'EOF' > envs/local-env/services-clusterip-patch.yaml
apiVersion: v1
kind: Service
metadata:
  name: wazuh
  namespace: wazuh
spec:
  type: ClusterIP
---
apiVersion: v1
kind: Service
metadata:
  name: wazuh-workers
  namespace: wazuh
spec:
  type: ClusterIP
---
apiVersion: v1
kind: Service
metadata:
  name: dashboard
  namespace: wazuh
spec:
  type: ClusterIP
EOF
```

### 13.5 — Consolidate kustomization.yml

The local-env `kustomization.yml` must have exactly **one** `patches:` block. YAML silently discards all but the last duplicate key, so appending additional `patches:` blocks causes earlier patches to be ignored. Write the complete file in one go:

```bash
cat <<'EOF' > envs/local-env/kustomization.yml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- ../../wazuh
patches:
  - path: storage-class.yaml
  - path: indexer-resources.yaml
  - path: wazuh-resources.yaml
  - path: services-clusterip-patch.yaml
EOF
```

Verify the rendered output includes the correct provisioner and ClusterIP services:
```bash
kubectl kustomize envs/local-env/ | grep -A5 "kind: StorageClass"
# Should show: provisioner: rancher.io/local-path

kubectl kustomize envs/local-env/ | grep -B2 -A3 "type: ClusterIP"
# Should show wazuh, wazuh-workers, and dashboard services
```

### 13.6 — Increase Wazuh manager resource limits

The upstream `wazuh-kubernetes` manifests set manager resource limits to 400m CPU / 512Mi memory. This is far too low for a cluster running Tetragon + Wazuh agents + indexer simultaneously — the managers will hit 100% CPU and become unresponsive, causing agent enrollment failures and connection drops.

Increase the limits directly in the base StatefulSet files:

```bash
sed -i 's/cpu: 400m/cpu: "2"/; s/memory: 512Mi/memory: 2Gi/' wazuh/wazuh_managers/wazuh-master-sts.yaml
sed -i 's/cpu: 400m/cpu: "2"/; s/memory: 512Mi/memory: 2Gi/' wazuh/wazuh_managers/wazuh-worker-sts.yaml
```

Verify:
```bash
grep -A4 "resources:" wazuh/wazuh_managers/wazuh-master-sts.yaml
grep -A4 "resources:" wazuh/wazuh_managers/wazuh-worker-sts.yaml
# Both should show: cpu: "2" and memory: 2Gi
```

> **Why edit the base files?** Same reason as the StorageClass fix — these values need to be correct before Kustomize renders the manifests. The `wazuh-resources.yaml` overlay only controls worker replica count, not resource limits.

### 13.7 — Deploy with Kustomize

```bash
kubectl apply -k envs/local-env/
```

This creates in the `wazuh` namespace: namespace, secrets, configmaps, StatefulSets (`wazuh-manager-master`, `wazuh-manager-worker-0`, `wazuh-indexer`), Deployment (`wazuh-dashboard`), and all services.

> **If redeploying after a failed attempt:** Namespace deletion is asynchronous. If you run `kubectl delete -k envs/local-env/` followed immediately by `kubectl apply`, the apply will fail because the namespace is still terminating. Always wait for the namespace to fully disappear before re-applying:
> ```bash
> kubectl delete -k envs/local-env/
> # Wait for the namespace to be fully removed
> kubectl get ns wazuh -w
> # Once it shows "NotFound" or disappears, proceed:
> kubectl apply -k envs/local-env/
> ```

### 13.8 — Wait for all pods to become Ready

First-run image pulls plus indexer cluster bootstrapping take 3–10 minutes.

```bash
# Watch all wazuh pods
kubectl get pods -n wazuh -w

# Or wait on each component explicitly
kubectl rollout status statefulset/wazuh-indexer -n wazuh --timeout=600s
kubectl rollout status statefulset/wazuh-manager-master -n wazuh --timeout=300s
kubectl rollout status statefulset/wazuh-manager-worker-0 -n wazuh --timeout=300s
kubectl rollout status deployment/wazuh-dashboard -n wazuh --timeout=300s
```

Target steady state:
```
NAME                              READY   STATUS    RESTARTS
wazuh-indexer-0                   1/1     Running   0
wazuh-dashboard-<hash>            1/1     Running   0
wazuh-manager-master-0            1/1     Running   0
wazuh-manager-worker-0-0          1/1     Running   0
```

### 13.9 — Verify secrets created by the deployment

The `wazuh-kubernetes` deployment automatically creates several secrets. Two are critical for the agent setup:

```bash
kubectl get secret -n wazuh
```

You should see (among others):
- `wazuh-authd-pass` — enrollment password for agents to authenticate with the manager via authd
- `wazuh-api-cred` — credentials for the Wazuh manager REST API (used by the agent deregistration script)

Verify the authd password:
```bash
kubectl get secret wazuh-authd-pass -n wazuh -o jsonpath='{.data}' | python3 -c "
import sys, json, base64
data = json.load(sys.stdin)
for k, v in data.items():
    print(f'{k}: {base64.b64decode(v).decode()}')"
```

### 13.10 — Access the Wazuh dashboard

```bash
# Run in a separate terminal or background it
kubectl port-forward svc/dashboard -n wazuh 8443:443 &
```

Open `https://localhost:8443`. Accept the self-signed certificate warning.

Default credentials: **admin / SecretPassword**

> Change the default password immediately via **Server Management → Security → Users** in the dashboard.

---

## Step 14 — Configure Tetragon Event Export

Tetragon (installed in Step 10) writes events to `/var/run/cilium/tetragon/tetragon.log` inside each Tetragon pod. This same path is bind-mounted to the **host filesystem** of each node, making it accessible to any process running on that node.

### 14.1 — Verify the log file is being written

```bash
TETRAGON_POD=$(kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon -o name | head -n1)

kubectl exec -n kube-system ${TETRAGON_POD} -c tetragon -- \
  tail -n 5 /var/run/cilium/tetragon/tetragon.log
```

You should see JSON lines. If the file is empty, proceed to 14.2.

### 14.2 — Enable the export file (if empty)

```bash
kubectl edit cm tetragon-config -n kube-system
```

Ensure these keys exist under `data:`:
```yaml
data:
  export-filename: "/var/run/cilium/tetragon/tetragon.log"
  export-file-max-size-mb: "100"
  export-file-rotation-interval: "24h"
```

Restart to apply:
```bash
kubectl rollout restart ds/tetragon -n kube-system
kubectl rollout status ds/tetragon -n kube-system -w
```

### 14.3 — Scope the export to lab namespaces (recommended)

This prevents Tetragon from flooding the log with `kube-system` noise:

```bash
kubectl edit cm tetragon-config -n kube-system
```

Add or update under `data:`:
```yaml
  export-allowlist: >
    {"event_set":["PROCESS_EXEC","PROCESS_EXIT","PROCESS_KPROBE"],
     "namespace":["vulnerable-apps","security-testing","wazuh"]}
```

Then restart:
```bash
kubectl rollout restart ds/tetragon -n kube-system
kubectl rollout status ds/tetragon -n kube-system -w
```

> Include `"wazuh"` in the namespace list if you want to detect events inside Wazuh's own namespace (useful for testing Active Response — see Step 18). Remove the `namespace` filter entirely to monitor all namespaces. The `event_set` filter should always be kept — it focuses on the three most security-relevant event types.

### 14.4 — Confirm events are flowing

```bash
# Terminal 1: watch the log
kubectl exec -n kube-system ${TETRAGON_POD} -c tetragon -- \
  tail -f /var/run/cilium/tetragon/tetragon.log

# Terminal 2: trigger an event
kubectl exec -it test-shell -n vulnerable-apps -- bash -c "cat /etc/shadow"
```

You should see a `{"process_exec": {...}}` JSON line appear immediately.

---

## Step 15 — Install Custom Tetragon Detection Rules

Tetragon events are JSON objects with top-level keys like `process_exec`, `process_exit`, and `process_kprobe`. Wazuh's built-in JSON decoder handles deserialization; these rules use dot-notation field matching to fire on the decoded fields.

### 15.1 — Add custom rules to the manager

```bash
kubectl exec -it wazuh-manager-master-0 -n wazuh -- bash -c 'cat > /var/ossec/etc/rules/0700-tetragon_rules.xml << '"'"'EOF'"'"'
<group name="tetragon,">

  <!-- ─── Base rules: match the three core Tetragon event types ─── -->

  <rule id="700000" level="3">
    <decoded_as>json</decoded_as>
    <field name="process_exec.process.exec_id">\.+</field>
    <options>no_full_log</options>
    <group>tetragon_exec,</group>
    <description>Tetragon: Process execution - $(process_exec.process.binary)</description>
  </rule>

  <rule id="700001" level="3">
    <decoded_as>json</decoded_as>
    <field name="process_exit.process.exec_id">\.+</field>
    <options>no_full_log</options>
    <group>tetragon_exit,</group>
    <description>Tetragon: Process exit - $(process_exit.process.binary)</description>
  </rule>

  <rule id="700002" level="3">
    <decoded_as>json</decoded_as>
    <field name="process_kprobe.process.exec_id">\.+</field>
    <options>no_full_log</options>
    <group>tetragon_kprobe,</group>
    <description>Tetragon: Kernel-level probe event detected</description>
  </rule>

  <!-- ─── Process exit with non-zero status (crash or failure) ─── -->

  <rule id="700003" level="5">
    <if_sid>700001</if_sid>
    <field name="process_exit.status">^[^0]</field>
    <options>no_full_log</options>
    <group>tetragon_exit,</group>
    <description>Tetragon: Process exited with non-zero status (possible crash)</description>
  </rule>

  <!-- ─── Shell spawned inside container ─── -->

  <rule id="700004" level="8">
    <if_sid>700000</if_sid>
    <field name="process_exec.process.binary">/usr/bin/sh|/bin/sh|/usr/bin/bash|/bin/bash|/usr/bin/zsh|/bin/zsh|/usr/bin/dash</field>
    <options>no_full_log</options>
    <group>tetragon_exec,container_shell,</group>
    <description>Tetragon: Shell spawned in container - possible interactive intrusion</description>
  </rule>

  <!-- ─── Outbound download tools ─── -->

  <rule id="700005" level="7">
    <if_sid>700000</if_sid>
    <field name="process_exec.process.binary">/usr/bin/curl|/bin/curl|/usr/bin/wget|/bin/wget</field>
    <options>no_full_log</options>
    <group>tetragon_exec,data_exfil,</group>
    <description>Tetragon: curl/wget executed in container</description>
  </rule>

  <!-- ─── Package manager inside container ─── -->

  <rule id="700006" level="7">
    <if_sid>700000</if_sid>
    <field name="process_exec.process.binary">/usr/bin/apt|/usr/bin/apt-get|/usr/bin/dpkg|/usr/bin/yum|/usr/bin/dnf|/usr/bin/apk|/usr/bin/rpm</field>
    <options>no_full_log</options>
    <group>tetragon_exec,package_install,</group>
    <description>Tetragon: Package manager executed in container - possible unauthorized install</description>
  </rule>

  <!-- ─── Sensitive file access ─── -->

  <rule id="700007" level="10">
    <if_sid>700000</if_sid>
    <field name="process_exec.process.arguments">/etc/shadow|/etc/passwd|/etc/sudoers|/root/.ssh/|/proc/</field>
    <options>no_full_log</options>
    <group>tetragon_exec,sensitive_file,</group>
    <description>Tetragon: Sensitive system file accessed</description>
  </rule>

  <!-- ─── Privilege escalation tools ─── -->

  <rule id="700008" level="10">
    <if_sid>700000</if_sid>
    <field name="process_exec.process.binary">/usr/bin/sudo|/bin/su|/usr/bin/su|/usr/sbin/usermod|/usr/sbin/useradd</field>
    <options>no_full_log</options>
    <group>tetragon_exec,priv_escalation,</group>
    <description>Tetragon: Privilege escalation tool executed - $(process_exec.process.binary)</description>
  </rule>

  <!-- ─── Kubernetes namespace-aware rules ─── -->

  <rule id="700010" level="9">
    <if_sid>700004</if_sid>
    <field name="process_exec.process.pod.namespace">vulnerable-apps</field>
    <options>no_full_log</options>
    <group>tetragon_exec,container_shell,k8s_aware,</group>
    <description>Tetragon: Shell spawned in vulnerable-apps/$(process_exec.process.pod.name)</description>
  </rule>

  <rule id="700011" level="8">
    <if_sid>700005</if_sid>
    <field name="process_exec.process.pod.namespace">vulnerable-apps</field>
    <options>no_full_log</options>
    <group>tetragon_exec,data_exfil,k8s_aware,</group>
    <description>Tetragon: curl/wget in vulnerable-apps/$(process_exec.process.pod.name)</description>
  </rule>

  <!-- ─── Kernel-level network connections (from TracingPolicies) ─── -->

  <rule id="700020" level="6">
    <if_sid>700002</if_sid>
    <field name="process_kprobe.function_name">tcp_connect|ip4_datagram_connect</field>
    <options>no_full_log</options>
    <group>tetragon_kprobe,network,</group>
    <description>Tetragon: Outbound TCP/UDP connection at kernel level from $(process_kprobe.process.binary)</description>
  </rule>

</group>
EOF'
```

### 15.2 — Configure Active Response on the manager

Active Response allows Wazuh to take automated action when specific rules fire. We configure the manager to execute a pod-deletion script on the agent when rule 700005 (curl/wget detected) is triggered.

Edit the Wazuh manager ConfigMap to add the Active Response block:
```bash
kubectl edit cm wazuh-conf -n wazuh
```

Add the following inside the `<ossec_config>` block of **both** the master and worker configurations:
```xml
  <command>
    <name>delete-pod</name>
    <executable>delete-pod.py</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>delete-pod</command>
    <location>local</location>
    <rules_id>700005</rules_id>
  </active-response>
```

> **What this does:** When rule 700005 fires (curl or wget detected in a container), the Wazuh manager instructs the agent on the same node to execute `delete-pod.py`. The script uses the Kubernetes API to delete the offending pod. You can change `<rules_id>` to trigger on different rules (e.g., 700004 for any shell spawn).

### 15.3 — Verify rules syntax and restart the manager

```bash
kubectl exec -it wazuh-manager-master-0 -n wazuh -- \
  /var/ossec/bin/wazuh-logtest -t

kubectl rollout restart statefulset/wazuh-manager-master -n wazuh
kubectl rollout restart statefulset/wazuh-manager-worker-0 -n wazuh

kubectl rollout status statefulset/wazuh-manager-master -n wazuh --timeout=120s
kubectl rollout status statefulset/wazuh-manager-worker-0 -n wazuh --timeout=120s
```

### 15.4 — Create an agent group for centralized configuration (optional)

Instead of configuring each agent individually, create a group in the Wazuh dashboard that all agents will join. This allows managing agent configuration centrally from the manager.

In the Wazuh dashboard (`https://localhost:8443`):
1. Navigate to **Server Management → Endpoint Groups**
2. Click **Add new group**, name it `k8s-nodes`
3. Edit the group configuration (`agent.conf`) and add:

```xml
<agent_config>
  <localfile>
    <log_format>json</log_format>
    <location>/host/var/run/cilium/tetragon/tetragon.log</location>
  </localfile>
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <directories>/host/etc,/host/usr/bin,/host/usr/sbin</directories>
    <directories>/host/bin,/host/sbin,/host/boot</directories>
    <ignore>/host/etc/mtab</ignore>
    <ignore>/host/etc/hosts.deny</ignore>
    <ignore>/host/etc/random-seed</ignore>
    <ignore>/host/etc/adjtime</ignore>
    <ignore type="sregex">.log$|.swp$</ignore>
    <nodiff>/host/etc/ssl/private.key</nodiff>
    <skip_nfs>yes</skip_nfs>
    <skip_dev>yes</skip_dev>
    <skip_proc>yes</skip_proc>
    <skip_sys>yes</skip_sys>
    <process_priority>10</process_priority>
    <max_eps>50</max_eps>
    <synchronization>
      <enabled>yes</enabled>
      <interval>5m</interval>
      <max_eps>10</max_eps>
    </synchronization>
  </syscheck>
</agent_config>
```

> This configures Tetragon log forwarding and host filesystem integrity monitoring for all agents in the group. The `/host/` prefix maps to the host filesystem via the agent's volume mounts (configured in Step 16).

---

## Step 16 — Build the Wazuh Agent Image

The Wazuh agent DaemonSet uses a **custom Docker image** that includes the Wazuh agent binary, Python dependencies for Active Response, and the pod-deletion script. This approach is simpler and more reliable than the multi-init-container pattern — a single startup script handles configuration and launch.

### 16.1 — Create the agent build directory

```bash
mkdir -p ~/K8s/wazuh-agent-image && cd ~/K8s/wazuh-agent-image
```

### 16.2 — Create the Active Response script

This script is executed by the Wazuh agent when the manager triggers an Active Response. It uses the Kubernetes API (via in-cluster credentials from the ServiceAccount) to delete the offending pod identified in the Tetragon event.

```bash
cat <<'PYEOF' > delete-pod.py
#!/usr/bin/python3
import os
import sys
import json
import datetime
from pathlib import PureWindowsPath, PurePosixPath

try:
    import kubernetes
except ImportError:
    pass

if os.name == 'nt':
    LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"

ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3

OS_SUCCESS = 0
OS_INVALID = -1


class message:
    def __init__(self):
        self.alert = ""
        self.command = 0


def write_debug_file(ar_name, msg):
    with open(LOG_FILE, mode="a") as log_file:
        ar_name_posix = str(PurePosixPath(PureWindowsPath(
            ar_name[ar_name.find("active-response"):])))
        log_file.write(
            str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S'))
            + " " + ar_name_posix + ": " + msg + "\n")


def setup_and_check_message(argv):
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        message.command = OS_INVALID
        return message

    message.alert = data

    command = data.get("command")

    if command == "add":
        message.command = ADD_COMMAND
    elif command == "delete":
        message.command = DELETE_COMMAND
    else:
        message.command = OS_INVALID
        write_debug_file(argv[0], 'Not valid command: ' + command)

    return message


def send_keys_and_check_message(argv, keys):
    keys_msg = json.dumps({
        "version": 1,
        "origin": {"name": argv[0], "module": "active-response"},
        "command": "check_keys",
        "parameters": {"keys": keys}
    })

    write_debug_file(argv[0], keys_msg)
    print(keys_msg)
    sys.stdout.flush()

    input_str = ""
    while True:
        line = sys.stdin.readline()
        if line:
            input_str = line
            break

    write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        return message

    action = data.get("command")

    if "continue" == action:
        ret = CONTINUE_COMMAND
    elif "abort" == action:
        ret = ABORT_COMMAND
    else:
        ret = OS_INVALID
        write_debug_file(argv[0], "Invalid value of 'command'")

    return ret


def main(argv):
    write_debug_file(argv[0], "Started")

    msg = setup_and_check_message(argv)

    if msg.command < 0:
        sys.exit(OS_INVALID)

    if msg.command == ADD_COMMAND:
        alert = msg.alert["parameters"]["alert"]
        keys = [alert["rule"]["id"]]

        # Extract pod name and namespace from the Tetragon event
        pod = alert["data"]["process_exec"]["process"]["pod"]["name"]
        namespace = alert["data"]["process_exec"]["process"]["pod"]["namespace"]

        try:
            kubernetes.config.load_incluster_config()
            write_debug_file(argv[0], "Using in-cluster config")
            write_debug_file(argv[0], f"Deleting pod: {namespace}/{pod}")

            api = kubernetes.client.CoreV1Api()
            api.delete_namespaced_pod(namespace=namespace, name=pod)
            write_debug_file(argv[0], f"Pod {namespace}/{pod} deleted successfully")
        except kubernetes.config.ConfigException:
            write_debug_file(argv[0], "Failed to load in-cluster config")
        except Exception as e:
            write_debug_file(argv[0], f"Error deleting pod: {str(e)}")

    elif msg.command == DELETE_COMMAND:
        pass

    else:
        write_debug_file(argv[0], "Invalid command")

    write_debug_file(argv[0], "Ended")
    sys.exit(OS_SUCCESS)


if __name__ == "__main__":
    main(sys.argv)
PYEOF
```

### 16.3 — Create the Dockerfile

```bash
cat <<'DEOF' > Dockerfile
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && \
    apt-get install -y curl procps gnupg apt-transport-https lsb-release && \
    rm -rf /var/lib/apt/lists/*

# Install Wazuh agent
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    WAZUH_MANAGER="placeholder" apt-get install -y wazuh-agent=4.14.1-1 && \
    rm -rf /var/lib/apt/lists/*

# Install Python packages for Active Response
RUN python3 -m ensurepip 2>/dev/null || apt-get update && apt-get install -y python3-pip && \
    pip3 install requests kubernetes --break-system-packages 2>/dev/null || \
    pip3 install requests kubernetes

# Install Active Response script
COPY delete-pod.py /var/ossec/active-response/bin/delete-pod.py
RUN chmod 750 /var/ossec/active-response/bin/delete-pod.py && \
    chown root:wazuh /var/ossec/active-response/bin/delete-pod.py

ENTRYPOINT ["/bin/bash"]
DEOF
```

### 16.4 — Build and load the image into kind

```bash
docker build -t wazuh-agent-local:4.14.1 .
kind load docker-image wazuh-agent-local:4.14.1 --name security-lab
```

Verify the image is available in the cluster:
```bash
docker exec security-lab-worker crictl images | grep wazuh-agent-local
```

---

## Step 17 — Deploy Wazuh Agent DaemonSet

The Wazuh agent DaemonSet runs one agent per cluster node (3 total: control-plane + 2 workers). Each agent registers with the Wazuh manager, reads the Tetragon log from the host filesystem, and forwards events to the manager for analysis.

### 17.1 — Create the agent ConfigMap

This ConfigMap contains three files: the startup script, the ossec.conf configuration, and the deregistration script.

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: wazuh-agent-scripts
  namespace: wazuh
data:
  script.sh: |
    #!/bin/bash
    set -e
    echo "[startup] Configuring Wazuh agent..."

    # Read authd password from mounted secret file
    # (The wazuh-authd-pass secret key is "authd.pass" which contains a dot,
    #  making it invalid as a Linux environment variable name. Kubernetes
    #  envFrom silently skips such keys, so we mount the secret as a file instead.)
    if [ -f /secret/authd.pass ]; then
      cat /secret/authd.pass | tr -d '\n' > /var/ossec/etc/authd.pass
      echo "[startup] Password loaded from mounted secret"
    else
      echo "[startup] WARNING: /secret/authd.pass not found!"
    fi
    # wazuh-agentd drops privileges to the "wazuh" group — file must be group-readable
    chown root:wazuh /var/ossec/etc/authd.pass 2>/dev/null || chown root:ossec /var/ossec/etc/authd.pass
    chmod 640 /var/ossec/etc/authd.pass

    # Copy ossec.conf from ConfigMap mount
    cp /scripts/ossec.conf /var/ossec/etc/ossec.conf

    # Clean stale PID/lock files from previous runs
    rm -f /var/ossec/var/run/*.pid 2>/dev/null || true
    rm -f /var/ossec/queue/ossec/*.lock 2>/dev/null || true

    echo "[startup] Starting Wazuh agent..."
    /var/ossec/bin/wazuh-control start

    # Keep container alive and stream logs
    tail -f /var/ossec/logs/ossec.log

  deregister.py: |
    #!/usr/bin/python3
    """Deregister this agent from the Wazuh manager on pod termination."""
    import requests
    import os
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    username = os.getenv("username", "wazuh-wui")
    password = os.getenv("password", "")
    server_ip = os.getenv("WAZUH_SERVICE_HOST",
                          "wazuh.wazuh.svc.cluster.local")
    hostname = os.getenv("HOSTNAME", "")

    def login():
        try:
            resp = requests.post(
                f"https://{server_ip}:55000/security/user/authenticate?raw=true",
                verify=False,
                auth=(username, password),
                timeout=10)
            return resp.content.decode('utf-8') if resp.status_code == 200 else None
        except Exception as e:
            print(f"Login failed: {e}")
            return None

    def find_and_delete():
        token = login()
        if not token:
            print("Could not authenticate with Wazuh API")
            return

        headers = {"Authorization": f"Bearer {token}"}
        try:
            resp = requests.get(
                f"https://{server_ip}:55000/agents?pretty=true&sort=name",
                verify=False, headers=headers, timeout=10)
            agents = resp.json().get('data', {}).get('affected_items', [])
            for agent in agents:
                if agent.get('name') == hostname:
                    agent_id = agent['id']
                    print(f"Deregistering agent {hostname} (ID: {agent_id})")
                    requests.delete(
                        f"https://{server_ip}:55000/agents?"
                        f"pretty=true&older_than=0s&agents_list={agent_id}&status=all",
                        verify=False, headers=headers, timeout=10)
                    print(f"Agent {agent_id} deregistered")
                    return
            print(f"Agent {hostname} not found in manager")
        except Exception as e:
            print(f"Deregistration failed: {e}")

    if __name__ == "__main__":
        find_and_delete()

  ossec.conf: |
    <ossec_config>
      <client>
        <server>
          <address>wazuh-workers.wazuh.svc.cluster.local</address>
          <port>1514</port>
          <protocol>tcp</protocol>
        </server>
        <config-profile>ubuntu, ubuntu22, ubuntu22.04</config-profile>
        <notify_time>10</notify_time>
        <time-reconnect>60</time-reconnect>
        <auto_restart>yes</auto_restart>
        <crypto_method>aes</crypto_method>
        <enrollment>
          <manager_address>wazuh.wazuh.svc.cluster.local</manager_address>
          <enabled>yes</enabled>
          <groups>k8s-nodes</groups>
          <authorization_pass_path>etc/authd.pass</authorization_pass_path>
        </enrollment>
      </client>

      <client_buffer>
        <disabled>no</disabled>
        <queue_size>5000</queue_size>
        <events_per_second>500</events_per_second>
      </client_buffer>

      <!-- Collect Tetragon eBPF events as JSON -->
      <localfile>
        <log_format>json</log_format>
        <location>/host/var/run/cilium/tetragon/tetragon.log</location>
      </localfile>

      <!-- Basic syslog collection -->
      <localfile>
        <log_format>syslog</log_format>
        <location>/var/log/syslog</location>
      </localfile>

      <!-- System commands -->
      <localfile>
        <log_format>command</log_format>
        <command>df -P</command>
        <frequency>360</frequency>
      </localfile>

      <localfile>
        <log_format>full_command</log_format>
        <command>netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\(.*\):\([[:digit:]]*\)\ \+\([0-9\.\:\*]\+\).\+\ \([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 == \3 == \4 \5/' | sort -k 4 -g | sed 's/ == \(.*\) ==/:\1/' | sed 1,2d</command>
        <alias>netstat listening ports</alias>
        <frequency>360</frequency>
      </localfile>

      <localfile>
        <log_format>full_command</log_format>
        <command>last -n 20</command>
        <frequency>360</frequency>
      </localfile>

      <!-- Active Response -->
      <active-response>
        <disabled>no</disabled>
        <ca_store>etc/wpk_root.pem</ca_store>
        <ca_verification>yes</ca_verification>
      </active-response>

      <!-- Policy monitoring -->
      <rootcheck>
        <disabled>no</disabled>
        <check_files>yes</check_files>
        <check_trojans>yes</check_trojans>
        <check_dev>yes</check_dev>
        <check_sys>yes</check_sys>
        <check_pids>yes</check_pids>
        <check_ports>yes</check_ports>
        <check_if>yes</check_if>
        <frequency>43200</frequency>
        <rootkit_files>etc/shared/rootkit_files.txt</rootkit_files>
        <rootkit_trojans>etc/shared/rootkit_trojans.txt</rootkit_trojans>
        <skip_nfs>yes</skip_nfs>
        <ignore>/var/lib/containerd</ignore>
        <ignore>/var/lib/docker/overlay2</ignore>
      </rootcheck>

      <!-- System inventory -->
      <wodle name="syscollector">
        <disabled>no</disabled>
        <interval>1h</interval>
        <scan_on_start>yes</scan_on_start>
        <hardware>yes</hardware>
        <os>yes</os>
        <network>yes</network>
        <packages>yes</packages>
        <ports all="no">yes</ports>
        <processes>yes</processes>
        <synchronization>
          <max_eps>10</max_eps>
        </synchronization>
      </wodle>

      <!-- File integrity monitoring (disabled — use group config instead) -->
      <syscheck>
        <disabled>yes</disabled>
      </syscheck>

      <sca>
        <enabled>yes</enabled>
        <scan_on_start>yes</scan_on_start>
        <interval>12h</interval>
        <skip_nfs>yes</skip_nfs>
      </sca>

      <logging>
        <log_format>plain</log_format>
      </logging>
    </ossec_config>

    <ossec_config>
      <localfile>
        <log_format>syslog</log_format>
        <location>/var/ossec/logs/active-responses.log</location>
      </localfile>
    </ossec_config>
EOF
```

### 17.2 — Create the ServiceAccount with cluster-admin privileges

The agent needs elevated permissions to delete pods via Active Response:

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: wazuh-agent-sa
  namespace: wazuh
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: wazuh-agent-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: wazuh-agent-sa
  namespace: wazuh
EOF
```

> **Security note:** `cluster-admin` is used here for lab simplicity. In production, scope this to only the `delete pods` verb on the target namespaces.

### 17.3 — Deploy the DaemonSet

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: wazuh-agent
  namespace: wazuh
  labels:
    app: wazuh-agent
spec:
  selector:
    matchLabels:
      app: wazuh-agent
  template:
    metadata:
      labels:
        app: wazuh-agent
    spec:
      serviceAccountName: wazuh-agent-sa
      hostNetwork: true
      hostPID: true
      dnsPolicy: ClusterFirstWithHostNet
      terminationGracePeriodSeconds: 30
      containers:
      - name: wazuh-agent
        image: wazuh-agent-local:4.14.1
        imagePullPolicy: Never
        command: ["/bin/bash", "/scripts/script.sh"]
        envFrom:
        - secretRef:
            name: wazuh-api-cred
        securityContext:
          privileged: true
        resources:
          requests:
            cpu: 100m
            memory: 256Mi
          limits:
            cpu: 500m
            memory: 512Mi
        volumeMounts:
        - name: scripts
          mountPath: /scripts
        - name: authd-secret
          mountPath: /secret
          readOnly: true
        - name: var-run
          mountPath: /host/var/run
          readOnly: true
        - name: var-log
          mountPath: /host/var/log
          readOnly: true
        - name: etc
          mountPath: /host/etc
          readOnly: true
        - name: sys
          mountPath: /host/sys
          readOnly: true
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: boot
          mountPath: /host/boot
          readOnly: true
        - name: modules
          mountPath: /host/lib/modules
          readOnly: true
      volumes:
      - name: scripts
        configMap:
          name: wazuh-agent-scripts
      - name: authd-secret
        secret:
          secretName: wazuh-authd-pass
      - name: var-run
        hostPath:
          path: /var/run
      - name: var-log
        hostPath:
          path: /var/log
      - name: etc
        hostPath:
          path: /etc
      - name: sys
        hostPath:
          path: /sys
      - name: proc
        hostPath:
          path: /proc
      - name: boot
        hostPath:
          path: /boot
      - name: modules
        hostPath:
          path: /lib/modules
EOF
```

**Key design decisions in this DaemonSet:**

| Setting | Why |
|---------|-----|
| `hostNetwork: true` | Agent reports with the node's hostname, matching Tetragon events |
| `hostPID: true` | Agent can see host processes for rootcheck and syscollector |
| `dnsPolicy: ClusterFirstWithHostNet` | Resolves cluster DNS (e.g., `wazuh.wazuh.svc`) even with hostNetwork |
| `privileged: true` | Required for host filesystem access and active response |
| `imagePullPolicy: Never` | Image was loaded via `kind load`, not from a registry |
| `authd-secret` volume mount | Mounts `wazuh-authd-pass` secret as a file at `/secret/authd.pass` — see note below |
| `envFrom` (wazuh-api-cred only) | Injects API credentials for the deregistration script |
| Comprehensive host mounts | `/var/run` (Tetragon log), `/etc`, `/var/log`, `/proc`, `/sys`, `/boot`, `/lib/modules` |

> **Why mount `authd-pass` as a file instead of using `envFrom`?** The `wazuh-authd-pass` secret has a key named `authd.pass` (with a dot). Dots are not valid in Linux environment variable names, so Kubernetes `envFrom` silently skips the key — resulting in an empty password file and enrollment failures with `"No authentication password provided"`. Mounting the secret as a volume at `/secret/` avoids this entirely.
>
> **Why no `preStop` lifecycle hook?** During DaemonSet rolling updates, the old pod's `preStop` hook fires *after* the new pod has already enrolled. The deregistration script deletes the agent entry that the new pod just created, causing a permanent enrollment/connection failure loop. If you need deregistration (e.g., for cluster teardown), run the deregister script manually or use a Job instead.

### 17.4 — Watch agents start up

```bash
kubectl get pods -n wazuh -l app=wazuh-agent -w
```

Each pod should reach `Running` within 30–60 seconds. Check the agent logs:
```bash
# Pick any agent pod
AGENT_POD=$(kubectl -n wazuh get pods -l app=wazuh-agent -o name | head -n1)
kubectl logs -n wazuh ${AGENT_POD}
```

Look for:
```
[startup] Starting Wazuh agent...
Started wazuh-agentd...
Started wazuh-execd...
Started wazuh-modulesd...
Started wazuh-logcollector...
Started wazuh-syscheckd...
```

### 17.5 — Verify agents registered in Wazuh

```bash
# Check manager logs for successful registrations
kubectl logs wazuh-manager-master-0 -n wazuh | grep "New agent" | tail -10

# List all registered agents
kubectl exec -it wazuh-manager-master-0 -n wazuh -- \
  /var/ossec/bin/manage_agents -l
```

You should see three agents — one per cluster node (named after the node hostnames).

---

## Step 18 — Verify End-to-End Integration

### 18.1 — Open three terminals

**Terminal 1 — live Wazuh alert stream:**
```bash
kubectl exec -it wazuh-manager-master-0 -n wazuh -- \
  tail -f /var/ossec/logs/alerts/alerts.json | \
  python3 -c "import sys, json; [print(json.dumps(json.loads(l), indent=2)) for l in sys.stdin]"
```

**Terminal 2 — live Tetragon compact view:**
```bash
POD=$(kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon -o name | head -n1)
kubectl exec -n kube-system ${POD} -c tetragon -- \
  tetra getevents -o compact --namespace vulnerable-apps
```

**Terminal 3 — trigger test events:**
```bash
kubectl exec -it test-shell -n vulnerable-apps -- bash
```

Inside the pod, run each command and watch terminals 1 and 2 respond:

```bash
cat /etc/shadow          # → rule 700007 (sensitive file access)
curl https://example.com # → rule 700005 + 700011 (curl, namespace-aware)
apt list 2>/dev/null     # → rule 700006 (package manager)
sudo id                  # → rule 700008 (privilege escalation tool)
# The exec into this pod above already triggered → rule 700004 + 700010 (shell in container)
```

### 18.2 — Test Active Response (pod deletion)

To test the Active Response mechanism, deploy a temporary test pod and trigger rule 700005:

```bash
# Deploy a test pod
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ar-test
  namespace: vulnerable-apps
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ar-test
  template:
    metadata:
      labels:
        app: ar-test
    spec:
      containers:
      - name: shell
        image: ubuntu:22.04
        command: ["/bin/sleep", "infinity"]
EOF

# Wait for it to be ready
kubectl wait --for=condition=ready pod -l app=ar-test -n vulnerable-apps --timeout=60s

# Exec in and trigger rule 700005
kubectl exec -it deploy/ar-test -n vulnerable-apps -- bash -c "curl https://example.com"
```

Watch the Wazuh alert stream (Terminal 1). You should see:
1. Rule 700005 fires (curl detected)
2. The Active Response triggers `delete-pod.py`
3. The pod is terminated (since it's a Deployment, a new pod spins up)

Check the Active Response logs on the agent:
```bash
AGENT_POD=$(kubectl -n wazuh get pods -l app=wazuh-agent -o name | head -n1)
kubectl exec -n wazuh ${AGENT_POD} -- \
  tail -20 /var/ossec/logs/active-responses.log
```

Clean up:
```bash
kubectl delete deployment ar-test -n vulnerable-apps
```

### 18.3 — Confirm alerts in the Wazuh dashboard

With `kubectl port-forward svc/dashboard -n wazuh 8443:443` running, open `https://localhost:8443`:

1. Navigate to **Threat Intelligence → Threat Hunting → Events**
2. Filter `rule.groups: "tetragon"` — shows all Tetragon-sourced alerts
3. Filter `rule.id: 700010` — shows shell-in-vulnerable-apps alerts specifically
4. Click any alert row to expand the full Tetragon JSON payload including pod name, namespace, binary path, parent process, and UID

---

## Cluster Health Check

Run at any point for a full status overview:

```bash
echo "=== Cluster Info ==="
kubectl cluster-info

echo -e "\n=== Nodes ==="
kubectl get nodes -o wide

echo -e "\n=== All Pods ==="
kubectl get pods -A

echo -e "\n=== Namespaces ==="
kubectl get namespaces

echo -e "\n=== Workloads in vulnerable-apps ==="
kubectl get pods -n vulnerable-apps

echo -e "\n=== Wazuh Stack (server + agents) ==="
kubectl get pods -n wazuh

echo -e "\n=== Tetragon ==="
kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon

echo -e "\n=== Services ==="
kubectl get svc -A

echo -e "\n=== Registered Wazuh Agents ==="
kubectl exec -it wazuh-manager-master-0 -n wazuh -- \
  /var/ossec/bin/manage_agents -l 2>/dev/null | grep "Name:"

echo -e "\n=== Recent Tetragon Alerts ==="
kubectl exec -it wazuh-manager-master-0 -n wazuh -- \
  grep '"tetragon"' /var/ossec/logs/alerts/alerts.json 2>/dev/null | tail -3 | \
  python3 -c "import sys,json; [print(json.loads(l).get('rule',{}).get('description','')) for l in sys.stdin]"

echo -e "\n=== Active Response Log (last 5 entries) ==="
AGENT_POD=$(kubectl -n wazuh get pods -l app=wazuh-agent -o name 2>/dev/null | head -n1)
if [ -n "${AGENT_POD}" ]; then
  kubectl exec -n wazuh ${AGENT_POD} -- \
    tail -5 /var/ossec/logs/active-responses.log 2>/dev/null || echo "No AR log entries"
fi
```

---

## Troubleshooting

### Agents not registering (pod stays in Running but no events)
```bash
# Check agent logs
AGENT_POD=$(kubectl -n wazuh get pods -l app=wazuh-agent -o name | head -n1)
kubectl logs -n wazuh ${AGENT_POD}

# Check if authd password was written correctly
kubectl exec -n wazuh ${AGENT_POD} -- cat /var/ossec/etc/authd.pass

# Verify the secret keys match what the startup script expects
kubectl get secret wazuh-authd-pass -n wazuh -o jsonpath='{.data}' | python3 -c "
import sys, json, base64
for k,v in json.load(sys.stdin).items(): print(f'Key: {k}')"

# Verify DNS resolves the manager from the agent pod
kubectl exec -n wazuh ${AGENT_POD} -- \
  getent hosts wazuh.wazuh.svc.cluster.local

# Check agent status
kubectl exec -n wazuh ${AGENT_POD} -- /var/ossec/bin/wazuh-control status
```

> **Common issue:** The `wazuh-authd-pass` secret key name varies between Wazuh versions. The startup script tries both `authd` and `authd.pass`. If neither works, check the actual key name with `kubectl get secret wazuh-authd-pass -n wazuh -o yaml` and update the script accordingly.

### Tetragon log file not found at host path
```bash
# Check the log exists inside the Tetragon pod
TETRAGON_POD=$(kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon -o name | head -n1)
kubectl exec -n kube-system ${TETRAGON_POD} -c tetragon -- \
  ls -la /var/run/cilium/tetragon/

# Check if the path exists on the kind node containers directly
docker exec security-lab-worker ls /var/run/cilium/tetragon/ 2>/dev/null || \
  echo "Not found on worker node — check Tetragon ConfigMap (Step 14.2)"

# Verify the agent can see the file via its mount
AGENT_POD=$(kubectl -n wazuh get pods -l app=wazuh-agent -o name | head -n1)
kubectl exec -n wazuh ${AGENT_POD} -- \
  ls -la /host/var/run/cilium/tetragon/
```

### Wazuh indexer pods stuck in Init
The OpenSearch indexer requires `vm.max_map_count=262144`. Set it on each kind node:
```bash
for node in $(kubectl get nodes -o name | sed 's|node/||'); do
  docker exec ${node} sysctl -w vm.max_map_count=262144
done
```

### Dashboard shows ERROR3099 — `wazuh-modulesd->failed`
The Wazuh dashboard refuses API connections with `ERROR3099 - Some Wazuh daemons are not ready yet in node "wazuh-manager-master" (wazuh-modulesd->failed)`. This typically means `wazuh-modulesd` crashed during startup.

Check the manager logs for the root cause:
```bash
kubectl exec -it wazuh-manager-master-0 -n wazuh -- \
  grep -iE "CRITICAL|modulesd.*ERROR" /var/ossec/logs/ossec.log | tail -10
```

**Most common cause:** `Couldn't init inotify: Too many open files`. The combined inotify pressure from Kubernetes controllers, Tetragon, and Wazuh exceeds the default Linux limit. Fix by raising limits on the host (kind nodes share the host kernel):

```bash
sudo sysctl -w fs.inotify.max_user_watches=524288
sudo sysctl -w fs.inotify.max_user_instances=512

# Make permanent
echo "fs.inotify.max_user_watches=524288" | sudo tee -a /etc/sysctl.conf
echo "fs.inotify.max_user_instances=512" | sudo tee -a /etc/sysctl.conf
```

Then restart the manager and verify all daemons recover:
```bash
kubectl exec -it wazuh-manager-master-0 -n wazuh -- /var/ossec/bin/wazuh-control restart
# Wait ~30 seconds
kubectl exec -it wazuh-manager-master-0 -n wazuh -- /var/ossec/bin/wazuh-control status
```

> See Step 6.1 for the recommended preventive setup during cluster creation.

### StorageClass "wazuh-storage" is invalid: provisioner: Required value
The `wazuh-kubernetes` repo ships with the provisioner commented out in `wazuh/base/storage-class.yaml`. Kustomize patches cannot add a field that is absent in the base.

```bash
# Check what provisioner your cluster uses
kubectl get sc

# Edit the base file directly (not the overlay patch)
cat <<'EOF' > wazuh/base/storage-class.yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: wazuh-storage
provisioner: rancher.io/local-path
reclaimPolicy: Delete
volumeBindingMode: WaitForFirstConsumer
EOF

# Verify kustomize renders it correctly
kubectl kustomize envs/local-env/ | grep -A5 "kind: StorageClass"
```

Also check that `envs/local-env/kustomization.yml` has only **one** `patches:` block. YAML silently discards all but the last duplicate key, so multiple `patches:` blocks cause earlier patches to be ignored.

### Namespace stuck in Terminating after failed deploy
If you delete and immediately re-apply, the namespace may still be terminating:
```bash
# Watch until the namespace fully disappears
kubectl get ns wazuh -w

# If stuck, check what resources are blocking deletion
kubectl get all -n wazuh
kubectl get pvc -n wazuh

# Only re-apply after the namespace is gone
kubectl apply -k envs/local-env/
```

### Custom rules not firing
Use `wazuh-logtest` to test a raw Tetragon JSON line interactively:
```bash
TETRAGON_POD=$(kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon -o name | head -n1)

# Grab a real log line
kubectl exec -n kube-system ${TETRAGON_POD} -c tetragon -- \
  tail -n 1 /var/run/cilium/tetragon/tetragon.log

# Paste it into the interactive tester
kubectl exec -it wazuh-manager-master-0 -n wazuh -- \
  /var/ossec/bin/wazuh-logtest
```

### Active Response not executing
```bash
# Check AR is enabled on the manager
kubectl exec -it wazuh-manager-master-0 -n wazuh -- \
  grep -A5 "active-response" /var/ossec/etc/ossec.conf

# Check the AR script exists on the agent
AGENT_POD=$(kubectl -n wazuh get pods -l app=wazuh-agent -o name | head -n1)
kubectl exec -n wazuh ${AGENT_POD} -- \
  ls -la /var/ossec/active-response/bin/delete-pod.py

# Check AR logs on the agent
kubectl exec -n wazuh ${AGENT_POD} -- \
  cat /var/ossec/logs/active-responses.log
```

### Agent deregistration not working on pod termination
```bash
# Manually test the deregister script
AGENT_POD=$(kubectl -n wazuh get pods -l app=wazuh-agent -o name | head -n1)
kubectl exec -n wazuh ${AGENT_POD} -- python3 /scripts/deregister.py

# Check if the wazuh-api-cred secret has the expected keys
kubectl get secret wazuh-api-cred -n wazuh -o jsonpath='{.data}' | python3 -c "
import sys, json, base64
for k,v in json.load(sys.stdin).items(): print(f'Key: {k} = {base64.b64decode(v).decode()}')"
```

---

## Teardown

```bash
# Delete the kind cluster (removes everything)
kind delete cluster --name security-lab

# Clean up host directories
rm -rf /tmp/kind-security-lab /tmp/wazuh-agent-ossec

# Clean up the agent image
docker rmi wazuh-agent-local:4.14.1 2>/dev/null
```

---

## Summary of All Components

| Component | Namespace | Kind | Purpose |
|-----------|-----------|------|---------|
| `tetragon` | `kube-system` | DaemonSet | eBPF kernel event capture on every node |
| `wazuh-manager-master` | `wazuh` | StatefulSet | SIEM core: rules engine, agent auth, API, Active Response |
| `wazuh-manager-worker-0` | `wazuh` | StatefulSet | Agent event ingestion worker |
| `wazuh-indexer-0` | `wazuh` | StatefulSet | OpenSearch — stores and indexes all alerts |
| `wazuh-dashboard` | `wazuh` | Deployment | Web UI for alert triage and rule management |
| `wazuh-agent` | `wazuh` | DaemonSet | 1 agent per node — reads Tetragon log, reports to manager, runs AR |
| `test-shell` | `vulnerable-apps` | Pod | Ubuntu shell for triggering test events |
| `test-nginx` | `vulnerable-apps` | Pod | Nginx with exposed sensitive ConfigMap |
| `test-privileged` | `vulnerable-apps` | Pod | Privileged container with host root mount |
| `test-network` | `vulnerable-apps` | Pod | Network tools container (netshoot) |
| `vulnerable-webapp` | `vulnerable-apps` | Deployment | DVWA exposed on NodePort 30000 |

## Key File Paths

| Path | Where | Description |
|------|-------|-------------|
| `/var/run/cilium/tetragon/tetragon.log` | Each node host filesystem | Tetragon eBPF event stream (JSON per line) |
| `/host/var/run/cilium/tetragon/tetragon.log` | Inside wazuh-agent pod | Same file, accessed via hostPath mount |
| `/var/ossec/etc/rules/0700-tetragon_rules.xml` | wazuh-manager-master-0 | Custom Tetragon detection rules |
| `/var/ossec/logs/alerts/alerts.json` | wazuh-manager-master-0 | All fired alert records |
| `/var/ossec/active-response/bin/delete-pod.py` | wazuh-agent pods | Active Response script for pod deletion |
| `/var/ossec/logs/active-responses.log` | wazuh-agent pods | Active Response execution log |
| `/var/ossec/etc/ossec.conf` | wazuh-agent pods (via ConfigMap) | Agent config including localfile stanza |
| `~/K8s/kind-security-cluster.yaml` | Host machine | Kind cluster definition |
| `~/K8s/wazuh-kubernetes/` | Host machine | Wazuh Kustomize manifests |
| `~/K8s/wazuh-agent-image/` | Host machine | Custom agent Docker image build context |

---

## Summary of Changes from Original Guide

| # | Original Issue | Fix Applied |
|---|---|---|
| 1 | Agent used fragile 4-step init container chain | Replaced with single ConfigMap startup script |
| 2 | Agent ran in separate `wazuh-agents` namespace | Moved to `wazuh` namespace — shares secrets and network context |
| 3 | Agent used official Docker image with incompatible entrypoint | Custom image built locally with `wazuh-agent` package + AR deps |
| 4 | No `hostNetwork` or `hostPID` | Added both — agent sees host processes and uses node hostname |
| 5 | `preStop` deregistration hook races with rolling updates | Removed `preStop` hook — old pod's deregister script deletes the agent entry the new pod just created, causing permanent enrollment failure |
| 6 | No Active Response capability | Added `delete-pod.py` AR script + manager AR config |
| 7 | Only mounted Tetragon log directory | Comprehensive host mounts: `/etc`, `/var/log`, `/proc`, `/sys`, `/boot`, `/lib/modules` |
| 8 | `ossec-data` stored on volatile `/tmp` hostPath | Agent state managed within container; ConfigMap provides reproducible config |
| 9 | No agent group management | Added `k8s-nodes` group with centralized agent config from dashboard |
| 10 | `dnsPolicy` not set with `hostNetwork` | Added `dnsPolicy: ClusterFirstWithHostNet` for cluster DNS resolution |
| 11 | Wazuh `LoadBalancer` services hang in kind | Patched all services to `ClusterIP`; dashboard via `port-forward` |
| 12 | Tetragon log path inconsistencies | Standardized all paths to `/var/run/cilium/tetragon/tetragon.log` |
| 13 | StorageClass provisioner commented out in base manifest | Set `rancher.io/local-path` directly in `wazuh/base/storage-class.yaml` for kind |
| 14 | Appending `patches:` to kustomization.yml creates duplicate keys | Consolidated into single `patches:` block written in one step |
| 15 | Default inotify limits too low for combined stack | Raised `max_user_watches` and `max_user_instances` on host (Step 6.1) — prevents `wazuh-modulesd` crash and ERROR3099 |
| 16 | Manager resource limits too low (400m CPU / 512Mi) | Increased to 2 CPU / 2Gi in base StatefulSet files (Step 13.6) — prevents manager CPU saturation and agent connection drops |
| 17 | `authd.pass` secret key skipped by `envFrom` (dot in name) | Mounted `wazuh-authd-pass` as a volume file at `/secret/authd.pass` instead of injecting via environment variables |
| 18 | `authd.pass` file owned by `root:root` with 640 permissions | Added `chown root:wazuh` in startup script — `wazuh-agentd` drops to `wazuh` group and needs group-read access |# Tetragon + Wazuh Security Lab — Complete Installation Guide

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                      kind cluster: security-lab                      │
│                                                                      │
│  kube-system            wazuh                                        │
│  ┌──────────────┐    ┌───────────────────────────────────────────┐   │
│  │   Tetragon   │    │  wazuh-manager-master  (StatefulSet)      │   │
│  │  (DaemonSet) │    │  wazuh-manager-worker  (StatefulSet)      │   │
│  │  eBPF hooks  │    │  wazuh-indexer         (StatefulSet)      │   │
│  └──────┬───────┘    │  wazuh-dashboard       (Deployment)       │   │
│         │            │  wazuh-agent            (DaemonSet)        │   │
│         │            └──────────────────────────┬────────────────┘   │
│         │  writes to       ▲  alerts via ossec  │                    │
│         │  host path       └────────────────────┘                    │
│         └─► /var/run/cilium/tetragon/tetragon.log (JSON)             │
│             ↑ mounted read-only into each wazuh-agent pod            │
│                                                                      │
│  vulnerable-apps         security-testing         monitoring         │
│  ┌──────────────────┐   ┌───────────────────┐   ┌──────────────┐    │
│  │ test-shell       │   │ security-test-sa  │   │ (reserved)   │    │
│  │ test-nginx       │   └───────────────────┘   └──────────────┘    │
│  │ test-privileged  │                                                │
│  │ test-network     │                                                │
│  │ vulnerable-webapp│                                                │
│  └──────────────────┘                                                │
└──────────────────────────────────────────────────────────────────────┘
```

**Data flow:**
1. Tetragon hooks into the Linux kernel via eBPF on each node, writing JSON events to `/var/run/cilium/tetragon/tetragon.log` on the host filesystem
2. Wazuh agent DaemonSet (in the `wazuh` namespace) mounts that host path at `/host/var/run/cilium/tetragon/tetragon.log` and reads it as a JSON `localfile` source
3. Wazuh agent forwards decoded events to the Wazuh manager worker over port 1514
4. Wazuh manager fires custom detection rules and Active Response actions, storing alerts in the Wazuh indexer
5. Wazuh dashboard provides a UI for alert triage, rule management, and agent oversight

---

## Part A — Infrastructure Setup

---

## Step 1 — Install Docker

```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
newgrp docker
rm get-docker.sh
```

Verify:
```bash
docker ps
```

---

## Step 2 — Install kubectl

```bash
curl -LO "https://dl.k8s.io/release/$(curl -Ls https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
rm kubectl
```

Verify:
```bash
kubectl version --client
```

---

## Step 3 — Install kind

```bash
[ $(uname -m) = x86_64 ] && curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.31.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind
kind --version
```

---

## Step 4 — Install Helm

```bash
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
helm version
```

---

## Step 5 — Install k9s (optional TUI)

```bash
wget https://github.com/derailed/k9s/releases/latest/download/k9s_linux_amd64.deb
sudo apt install ./k9s_linux_amd64.deb
rm k9s_linux_amd64.deb
```

---

## Step 6 — Create the Kind Cluster

Create the required host directory first:
```bash
mkdir -p /tmp/kind-security-lab
mkdir -p ~/K8s && cd ~/K8s
```

Create the cluster config:

```bash
cat <<EOF > kind-security-cluster.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: security-lab
nodes:
  - role: control-plane
    kubeadmConfigPatches:
    - |
      kind: InitConfiguration
      nodeRegistration:
        kubeletExtraArgs:
          node-labels: "node-type=control-plane"
    extraMounts:
      - hostPath: /tmp/kind-security-lab
        containerPath: /host-data
      - hostPath: /lib/modules
        containerPath: /lib/modules
        readOnly: true
      - hostPath: /usr/src
        containerPath: /usr/src
        readOnly: true
    extraPortMappings:
      - containerPort: 30000
        hostPort: 30000
        protocol: TCP
      - containerPort: 30001
        hostPort: 30001
        protocol: TCP
  - role: worker
    kubeadmConfigPatches:
    - |
      kind: JoinConfiguration
      nodeRegistration:
        kubeletExtraArgs:
          node-labels: "node-type=worker,workload=security-test"
    extraMounts:
      - hostPath: /tmp/kind-security-lab
        containerPath: /host-data
      - hostPath: /lib/modules
        containerPath: /lib/modules
        readOnly: true
      - hostPath: /usr/src
        containerPath: /usr/src
        readOnly: true
  - role: worker
    kubeadmConfigPatches:
    - |
      kind: JoinConfiguration
      nodeRegistration:
        kubeletExtraArgs:
          node-labels: "node-type=worker,workload=security-test"
    extraMounts:
      - hostPath: /tmp/kind-security-lab
        containerPath: /host-data
      - hostPath: /lib/modules
        containerPath: /lib/modules
        readOnly: true
      - hostPath: /usr/src
        containerPath: /usr/src
        readOnly: true
featureGates:
  "ProcMountType": true
networking:
  disableDefaultCNI: false
  podSubnet: "10.244.0.0/16"
  serviceSubnet: "10.96.0.0/12"
EOF
```

Create the cluster:
```bash
kind create cluster --config kind-security-cluster.yaml
```

Verify:
```bash
kubectl cluster-info --context kind-security-lab
kubectl get nodes
```

### 6.1 — Raise inotify limits for Wazuh

Wazuh's `wazuh-modulesd` daemon uses inotify watches internally. The default Linux limits are too low for a cluster running Kubernetes controllers + Tetragon + Wazuh simultaneously. Without this fix, `wazuh-modulesd` will crash with `CRITICAL: Couldn't init inotify: Too many open files`, causing the dashboard to show `ERROR3099 - Wazuh not ready yet`.

Set the limits on the **host machine** (kind nodes share the host kernel):

```bash
sudo sysctl -w fs.inotify.max_user_watches=524288
sudo sysctl -w fs.inotify.max_user_instances=512
```

Make permanent across reboots:
```bash
echo "fs.inotify.max_user_watches=524288" | sudo tee -a /etc/sysctl.conf
echo "fs.inotify.max_user_instances=512" | sudo tee -a /etc/sysctl.conf
```

> **Why here and not later?** These limits must be in place before Wazuh starts. If the cluster is already running and Wazuh is deployed, restart the manager after applying: `kubectl exec -it wazuh-manager-master-0 -n wazuh -- /var/ossec/bin/wazuh-control restart`

---

## Step 7 — Set Up Namespaces and RBAC

```bash
kubectl create namespace vulnerable-apps
kubectl create namespace security-testing
kubectl create namespace monitoring

kubectl label namespace vulnerable-apps env=test security=monitored
kubectl label namespace security-testing env=test security=monitored

# Service account for testing
kubectl create serviceaccount security-test-sa -n security-testing

cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: security-test-role
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["configmaps", "secrets"]
    verbs: ["get", "list"]
EOF

kubectl create clusterrolebinding security-test-binding \
  --clusterrole=security-test-role \
  --serviceaccount=security-testing:security-test-sa
```

---

## Step 8 — Install Metrics Server

```bash
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml

# Required patch for kind (skip TLS verification against kubelets)
kubectl patch deployment metrics-server -n kube-system --type='json' \
  -p='[{"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--kubelet-insecure-tls"}]'
```

---

## Step 9 — Deploy Test Workloads

### Shell pod

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-shell
  namespace: vulnerable-apps
  labels:
    app: test-shell
    security: monitored
spec:
  containers:
  - name: shell
    image: ubuntu:22.04
    command: ["/bin/sleep", "infinity"]
    securityContext:
      runAsNonRoot: false
      privileged: false
    volumeMounts:
    - name: host-data
      mountPath: /host-data
  volumes:
  - name: host-data
    hostPath:
      path: /tmp
      type: Directory
EOF
```

### Nginx pod with sensitive ConfigMap

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: sensitive-config
  namespace: vulnerable-apps
data:
  secret.txt: |
    This is sensitive data
    Database password: P@ssw0rd123
---
apiVersion: v1
kind: Pod
metadata:
  name: test-nginx
  namespace: vulnerable-apps
  labels:
    app: nginx
    security: monitored
spec:
  containers:
  - name: nginx
    image: nginx:latest
    ports:
    - containerPort: 80
    volumeMounts:
    - name: sensitive-data
      mountPath: /etc/sensitive
      readOnly: true
    - name: etc-volume
      mountPath: /host-etc
      readOnly: true
  volumes:
  - name: sensitive-data
    configMap:
      name: sensitive-config
  - name: etc-volume
    hostPath:
      path: /etc
      type: Directory
EOF
```

### Privileged pod

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-privileged
  namespace: vulnerable-apps
  labels:
    app: privileged-test
    security: monitored
spec:
  containers:
  - name: privileged-container
    image: busybox
    command: ["/bin/sh", "-c", "sleep infinity"]
    securityContext:
      privileged: true
      capabilities:
        add:
        - SYS_ADMIN
        - NET_ADMIN
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
      type: Directory
EOF
```

### Network tools pod

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-network
  namespace: vulnerable-apps
  labels:
    app: network-test
    security: monitored
spec:
  containers:
  - name: network-tools
    image: nicolaka/netshoot
    command: ["/bin/sleep", "infinity"]
EOF
```

### Vulnerable web app (DVWA)

```bash
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-webapp
  namespace: vulnerable-apps
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vulnerable-webapp
  template:
    metadata:
      labels:
        app: vulnerable-webapp
        security: monitored
    spec:
      containers:
      - name: webapp
        image: vulnerables/web-dvwa
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: vulnerable-webapp-svc
  namespace: vulnerable-apps
spec:
  type: NodePort
  ports:
  - port: 80
    targetPort: 80
    nodePort: 30000
  selector:
    app: vulnerable-webapp
EOF
```

### Secrets and ConfigMaps

```bash
kubectl create secret generic db-credentials \
  --from-literal=username=admin \
  --from-literal=password=SuperSecret123 \
  -n vulnerable-apps

kubectl create configmap app-config \
  --from-literal=api_key=sk-1234567890abcdef \
  --from-literal=database_url=postgresql://admin:password@db:5432/appdb \
  -n vulnerable-apps
```

---

## Step 10 — Install Tetragon

```bash
helm repo add cilium https://helm.cilium.io
helm repo update
helm install tetragon cilium/tetragon -n kube-system
kubectl rollout status -n kube-system ds/tetragon -w
```

Verify Tetragon pods are running:
```bash
kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon
```

---

## Step 11 — Stream Tetragon Events

```bash
# Get any Tetragon pod
POD=$(kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon -o name | head -n1)

# Stream all security events from the vulnerable-apps namespace
kubectl exec -n kube-system ${POD} -c tetragon -- \
  tetra getevents -o compact --namespace vulnerable-apps
```

To watch events scoped to a specific pod's node:
```bash
TARGET_NODE=$(kubectl get pod <your-pod-name> -n vulnerable-apps -o jsonpath='{.spec.nodeName}')

POD=$(kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon \
  -o name --field-selector spec.nodeName=${TARGET_NODE} | head -n1)

kubectl exec -n kube-system ${POD} -c tetragon -- \
  tetra getevents -o compact --namespace vulnerable-apps
```

---

## Step 12 — Trigger Test Events

In a separate terminal, exec into the test shell and run commands that Tetragon will detect:

```bash
kubectl exec -it test-shell -n vulnerable-apps -- bash
```

Inside the pod:
```bash
cat /etc/shadow          # sensitive file read
curl https://google.com  # outbound network connection
ps aux                   # process enumeration
ls -la /host-data        # host filesystem access
```

Watch the Tetragon terminal — each of the above should produce a security event in the event stream.

---

## Part B — Wazuh SIEM Integration

> **Resource check before continuing:** The Wazuh stack (manager + indexer + dashboard + agents) requires at minimum **6 vCPU** and **8 GB RAM** available across the cluster. Run `kubectl top nodes` to check headroom. If the host is constrained, temporarily stop test workloads with `kubectl delete pod test-shell test-nginx test-network -n vulnerable-apps` and restore them after Wazuh is stable.

---

## Step 13 — Deploy Wazuh Server

Wazuh provides an official Kubernetes repo (`wazuh/wazuh-kubernetes`) with Kustomize overlays. The `local-env` overlay reduces resource requests to fit a lab environment.

### 13.1 — Clone the repo

```bash
cd ~/K8s
git clone https://github.com/wazuh/wazuh-kubernetes.git -b v4.14.1 --depth=1
cd wazuh-kubernetes
```

> **Note:** v4.14.1 is the latest stable tagged release (November 2025). The `wazuh` namespace is created automatically by these manifests.

### 13.2 — Generate SSL certificates

Wazuh needs two sets of self-signed certificates: one for the OpenSearch indexer cluster, and one for the dashboard HTTPS endpoint.

```bash
# Indexer cluster certificates
chmod +x wazuh/certs/indexer_cluster/generate_certs.sh
bash wazuh/certs/indexer_cluster/generate_certs.sh

# Dashboard HTTPS certificate
chmod +x wazuh/certs/dashboard_http/generate_certs.sh
bash wazuh/certs/dashboard_http/generate_certs.sh
```

Verify certificates were created:
```bash
ls wazuh/certs/indexer_cluster/
# Expected: admin.pem  admin-key.pem  node.pem  node-key.pem  root-ca.pem

ls wazuh/certs/dashboard_http/
# Expected: cert.pem  key.pem
```

### 13.3 — Fix StorageClass provisioner for kind

The `wazuh-kubernetes` repo ships with the StorageClass provisioner commented out (or set to `microk8s.io/hostpath`). Kind uses `rancher.io/local-path` instead. The provisioner must be set **in the base file** — a Kustomize patch cannot add a field that is missing or commented out in the base.

First, confirm your cluster's provisioner:
```bash
kubectl get sc
# Expected output for kind:
# NAME                 PROVISIONER             ...
# standard (default)   rancher.io/local-path   ...
```

Edit the base StorageClass to set the correct provisioner:
```bash
cat <<'EOF' > wazuh/base/storage-class.yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: wazuh-storage
provisioner: rancher.io/local-path
reclaimPolicy: Delete
volumeBindingMode: WaitForFirstConsumer
EOF
```

> **Why edit the base instead of using a patch?** The upstream `storage-class.yaml` has the `provisioner` field commented out. Kustomize strategic merge patches can only override fields that already exist in the base manifest — they cannot add new fields. Editing the base directly is the only reliable fix.

### 13.4 — Patch services to ClusterIP for kind

By default `wazuh-kubernetes` creates `LoadBalancer` services. Kind has no cloud load-balancer controller, so those stay `<pending>` forever. Since everything runs inside the cluster, `ClusterIP` is correct for all services. Dashboard access uses `kubectl port-forward`.

```bash
cat <<'EOF' > envs/local-env/services-clusterip-patch.yaml
apiVersion: v1
kind: Service
metadata:
  name: wazuh
  namespace: wazuh
spec:
  type: ClusterIP
---
apiVersion: v1
kind: Service
metadata:
  name: wazuh-workers
  namespace: wazuh
spec:
  type: ClusterIP
---
apiVersion: v1
kind: Service
metadata:
  name: dashboard
  namespace: wazuh
spec:
  type: ClusterIP
EOF
```

### 13.5 — Consolidate kustomization.yml

The local-env `kustomization.yml` must have exactly **one** `patches:` block. YAML silently discards all but the last duplicate key, so appending additional `patches:` blocks causes earlier patches to be ignored. Write the complete file in one go:

```bash
cat <<'EOF' > envs/local-env/kustomization.yml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- ../../wazuh
patches:
  - path: storage-class.yaml
  - path: indexer-resources.yaml
  - path: wazuh-resources.yaml
  - path: services-clusterip-patch.yaml
EOF
```

Verify the rendered output includes the correct provisioner and ClusterIP services:
```bash
kubectl kustomize envs/local-env/ | grep -A5 "kind: StorageClass"
# Should show: provisioner: rancher.io/local-path

kubectl kustomize envs/local-env/ | grep -B2 -A3 "type: ClusterIP"
# Should show wazuh, wazuh-workers, and dashboard services
```

### 13.6 — Increase Wazuh manager resource limits

The upstream `wazuh-kubernetes` manifests set manager resource limits to 400m CPU / 512Mi memory. This is far too low for a cluster running Tetragon + Wazuh agents + indexer simultaneously — the managers will hit 100% CPU and become unresponsive, causing agent enrollment failures and connection drops.

Increase the limits directly in the base StatefulSet files:

```bash
sed -i 's/cpu: 400m/cpu: "2"/; s/memory: 512Mi/memory: 2Gi/' wazuh/wazuh_managers/wazuh-master-sts.yaml
sed -i 's/cpu: 400m/cpu: "2"/; s/memory: 512Mi/memory: 2Gi/' wazuh/wazuh_managers/wazuh-worker-sts.yaml
```

Verify:
```bash
grep -A4 "resources:" wazuh/wazuh_managers/wazuh-master-sts.yaml
grep -A4 "resources:" wazuh/wazuh_managers/wazuh-worker-sts.yaml
# Both should show: cpu: "2" and memory: 2Gi
```

> **Why edit the base files?** Same reason as the StorageClass fix — these values need to be correct before Kustomize renders the manifests. The `wazuh-resources.yaml` overlay only controls worker replica count, not resource limits.

### 13.7 — Deploy with Kustomize

```bash
kubectl apply -k envs/local-env/
```

This creates in the `wazuh` namespace: namespace, secrets, configmaps, StatefulSets (`wazuh-manager-master`, `wazuh-manager-worker-0`, `wazuh-indexer`), Deployment (`wazuh-dashboard`), and all services.

> **If redeploying after a failed attempt:** Namespace deletion is asynchronous. If you run `kubectl delete -k envs/local-env/` followed immediately by `kubectl apply`, the apply will fail because the namespace is still terminating. Always wait for the namespace to fully disappear before re-applying:
> ```bash
> kubectl delete -k envs/local-env/
> # Wait for the namespace to be fully removed
> kubectl get ns wazuh -w
> # Once it shows "NotFound" or disappears, proceed:
> kubectl apply -k envs/local-env/
> ```

### 13.8 — Wait for all pods to become Ready

First-run image pulls plus indexer cluster bootstrapping take 3–10 minutes.

```bash
# Watch all wazuh pods
kubectl get pods -n wazuh -w

# Or wait on each component explicitly
kubectl rollout status statefulset/wazuh-indexer -n wazuh --timeout=600s
kubectl rollout status statefulset/wazuh-manager-master -n wazuh --timeout=300s
kubectl rollout status statefulset/wazuh-manager-worker-0 -n wazuh --timeout=300s
kubectl rollout status deployment/wazuh-dashboard -n wazuh --timeout=300s
```

Target steady state:
```
NAME                              READY   STATUS    RESTARTS
wazuh-indexer-0                   1/1     Running   0
wazuh-dashboard-<hash>            1/1     Running   0
wazuh-manager-master-0            1/1     Running   0
wazuh-manager-worker-0-0          1/1     Running   0
```

### 13.9 — Verify secrets created by the deployment

The `wazuh-kubernetes` deployment automatically creates several secrets. Two are critical for the agent setup:

```bash
kubectl get secret -n wazuh
```

You should see (among others):
- `wazuh-authd-pass` — enrollment password for agents to authenticate with the manager via authd
- `wazuh-api-cred` — credentials for the Wazuh manager REST API (used by the agent deregistration script)

Verify the authd password:
```bash
kubectl get secret wazuh-authd-pass -n wazuh -o jsonpath='{.data}' | python3 -c "
import sys, json, base64
data = json.load(sys.stdin)
for k, v in data.items():
    print(f'{k}: {base64.b64decode(v).decode()}')"
```

### 13.10 — Access the Wazuh dashboard

```bash
# Run in a separate terminal or background it
kubectl port-forward svc/dashboard -n wazuh 8443:443 &
```

Open `https://localhost:8443`. Accept the self-signed certificate warning.

Default credentials: **admin / SecretPassword**

> Change the default password immediately via **Server Management → Security → Users** in the dashboard.

---

## Step 14 — Configure Tetragon Event Export

Tetragon (installed in Step 10) writes events to `/var/run/cilium/tetragon/tetragon.log` inside each Tetragon pod. This same path is bind-mounted to the **host filesystem** of each node, making it accessible to any process running on that node.

### 14.1 — Verify the log file is being written

```bash
TETRAGON_POD=$(kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon -o name | head -n1)

kubectl exec -n kube-system ${TETRAGON_POD} -c tetragon -- \
  tail -n 5 /var/run/cilium/tetragon/tetragon.log
```

You should see JSON lines. If the file is empty, proceed to 14.2.

### 14.2 — Enable the export file (if empty)

```bash
kubectl edit cm tetragon-config -n kube-system
```

Ensure these keys exist under `data:`:
```yaml
data:
  export-filename: "/var/run/cilium/tetragon/tetragon.log"
  export-file-max-size-mb: "100"
  export-file-rotation-interval: "24h"
```

Restart to apply:
```bash
kubectl rollout restart ds/tetragon -n kube-system
kubectl rollout status ds/tetragon -n kube-system -w
```

### 14.3 — Scope the export to lab namespaces (recommended)

This prevents Tetragon from flooding the log with `kube-system` noise:

```bash
kubectl edit cm tetragon-config -n kube-system
```

Add or update under `data:`:
```yaml
  export-allowlist: >
    {"event_set":["PROCESS_EXEC","PROCESS_EXIT","PROCESS_KPROBE"],
     "namespace":["vulnerable-apps","security-testing","wazuh"]}
```

Then restart:
```bash
kubectl rollout restart ds/tetragon -n kube-system
kubectl rollout status ds/tetragon -n kube-system -w
```

> Include `"wazuh"` in the namespace list if you want to detect events inside Wazuh's own namespace (useful for testing Active Response — see Step 18). Remove the `namespace` filter entirely to monitor all namespaces. The `event_set` filter should always be kept — it focuses on the three most security-relevant event types.

### 14.4 — Confirm events are flowing

```bash
# Terminal 1: watch the log
kubectl exec -n kube-system ${TETRAGON_POD} -c tetragon -- \
  tail -f /var/run/cilium/tetragon/tetragon.log

# Terminal 2: trigger an event
kubectl exec -it test-shell -n vulnerable-apps -- bash -c "cat /etc/shadow"
```

You should see a `{"process_exec": {...}}` JSON line appear immediately.

---

## Step 15 — Install Custom Tetragon Detection Rules

Tetragon events are JSON objects with top-level keys like `process_exec`, `process_exit`, and `process_kprobe`. Wazuh's built-in JSON decoder handles deserialization; these rules use dot-notation field matching to fire on the decoded fields.

### 15.1 — Add custom rules to the manager

```bash
kubectl exec -it wazuh-manager-master-0 -n wazuh -- bash -c 'cat > /var/ossec/etc/rules/0700-tetragon_rules.xml << '"'"'EOF'"'"'
<group name="tetragon,">

  <!-- ─── Base rules: match the three core Tetragon event types ─── -->

  <rule id="700000" level="3">
    <decoded_as>json</decoded_as>
    <field name="process_exec.process.exec_id">\.+</field>
    <options>no_full_log</options>
    <group>tetragon_exec,</group>
    <description>Tetragon: Process execution - $(process_exec.process.binary)</description>
  </rule>

  <rule id="700001" level="3">
    <decoded_as>json</decoded_as>
    <field name="process_exit.process.exec_id">\.+</field>
    <options>no_full_log</options>
    <group>tetragon_exit,</group>
    <description>Tetragon: Process exit - $(process_exit.process.binary)</description>
  </rule>

  <rule id="700002" level="3">
    <decoded_as>json</decoded_as>
    <field name="process_kprobe.process.exec_id">\.+</field>
    <options>no_full_log</options>
    <group>tetragon_kprobe,</group>
    <description>Tetragon: Kernel-level probe event detected</description>
  </rule>

  <!-- ─── Process exit with non-zero status (crash or failure) ─── -->

  <rule id="700003" level="5">
    <if_sid>700001</if_sid>
    <field name="process_exit.status">^[^0]</field>
    <options>no_full_log</options>
    <group>tetragon_exit,</group>
    <description>Tetragon: Process exited with non-zero status (possible crash)</description>
  </rule>

  <!-- ─── Shell spawned inside container ─── -->

  <rule id="700004" level="8">
    <if_sid>700000</if_sid>
    <field name="process_exec.process.binary">/usr/bin/sh|/bin/sh|/usr/bin/bash|/bin/bash|/usr/bin/zsh|/bin/zsh|/usr/bin/dash</field>
    <options>no_full_log</options>
    <group>tetragon_exec,container_shell,</group>
    <description>Tetragon: Shell spawned in container - possible interactive intrusion</description>
  </rule>

  <!-- ─── Outbound download tools ─── -->

  <rule id="700005" level="7">
    <if_sid>700000</if_sid>
    <field name="process_exec.process.binary">/usr/bin/curl|/bin/curl|/usr/bin/wget|/bin/wget</field>
    <options>no_full_log</options>
    <group>tetragon_exec,data_exfil,</group>
    <description>Tetragon: curl/wget executed in container</description>
  </rule>

  <!-- ─── Package manager inside container ─── -->

  <rule id="700006" level="7">
    <if_sid>700000</if_sid>
    <field name="process_exec.process.binary">/usr/bin/apt|/usr/bin/apt-get|/usr/bin/dpkg|/usr/bin/yum|/usr/bin/dnf|/usr/bin/apk|/usr/bin/rpm</field>
    <options>no_full_log</options>
    <group>tetragon_exec,package_install,</group>
    <description>Tetragon: Package manager executed in container - possible unauthorized install</description>
  </rule>

  <!-- ─── Sensitive file access ─── -->

  <rule id="700007" level="10">
    <if_sid>700000</if_sid>
    <field name="process_exec.process.arguments">/etc/shadow|/etc/passwd|/etc/sudoers|/root/.ssh/|/proc/</field>
    <options>no_full_log</options>
    <group>tetragon_exec,sensitive_file,</group>
    <description>Tetragon: Sensitive system file accessed</description>
  </rule>

  <!-- ─── Privilege escalation tools ─── -->

  <rule id="700008" level="10">
    <if_sid>700000</if_sid>
    <field name="process_exec.process.binary">/usr/bin/sudo|/bin/su|/usr/bin/su|/usr/sbin/usermod|/usr/sbin/useradd</field>
    <options>no_full_log</options>
    <group>tetragon_exec,priv_escalation,</group>
    <description>Tetragon: Privilege escalation tool executed - $(process_exec.process.binary)</description>
  </rule>

  <!-- ─── Kubernetes namespace-aware rules ─── -->

  <rule id="700010" level="9">
    <if_sid>700004</if_sid>
    <field name="process_exec.process.pod.namespace">vulnerable-apps</field>
    <options>no_full_log</options>
    <group>tetragon_exec,container_shell,k8s_aware,</group>
    <description>Tetragon: Shell spawned in vulnerable-apps/$(process_exec.process.pod.name)</description>
  </rule>

  <rule id="700011" level="8">
    <if_sid>700005</if_sid>
    <field name="process_exec.process.pod.namespace">vulnerable-apps</field>
    <options>no_full_log</options>
    <group>tetragon_exec,data_exfil,k8s_aware,</group>
    <description>Tetragon: curl/wget in vulnerable-apps/$(process_exec.process.pod.name)</description>
  </rule>

  <!-- ─── Kernel-level network connections (from TracingPolicies) ─── -->

  <rule id="700020" level="6">
    <if_sid>700002</if_sid>
    <field name="process_kprobe.function_name">tcp_connect|ip4_datagram_connect</field>
    <options>no_full_log</options>
    <group>tetragon_kprobe,network,</group>
    <description>Tetragon: Outbound TCP/UDP connection at kernel level from $(process_kprobe.process.binary)</description>
  </rule>

</group>
EOF'
```

### 15.2 — Configure Active Response on the manager

Active Response allows Wazuh to take automated action when specific rules fire. We configure the manager to execute a pod-deletion script on the agent when rule 700005 (curl/wget detected) is triggered.

Edit the Wazuh manager ConfigMap to add the Active Response block:
```bash
kubectl edit cm wazuh-conf -n wazuh
```

Add the following inside the `<ossec_config>` block of **both** the master and worker configurations:
```xml
  <command>
    <name>delete-pod</name>
    <executable>delete-pod.py</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>delete-pod</command>
    <location>local</location>
    <rules_id>700005</rules_id>
  </active-response>
```

> **What this does:** When rule 700005 fires (curl or wget detected in a container), the Wazuh manager instructs the agent on the same node to execute `delete-pod.py`. The script uses the Kubernetes API to delete the offending pod. You can change `<rules_id>` to trigger on different rules (e.g., 700004 for any shell spawn).

### 15.3 — Verify rules syntax and restart the manager

```bash
kubectl exec -it wazuh-manager-master-0 -n wazuh -- \
  /var/ossec/bin/wazuh-logtest -t

kubectl rollout restart statefulset/wazuh-manager-master -n wazuh
kubectl rollout restart statefulset/wazuh-manager-worker-0 -n wazuh

kubectl rollout status statefulset/wazuh-manager-master -n wazuh --timeout=120s
kubectl rollout status statefulset/wazuh-manager-worker-0 -n wazuh --timeout=120s
```

### 15.4 — Create an agent group for centralized configuration (optional)

Instead of configuring each agent individually, create a group in the Wazuh dashboard that all agents will join. This allows managing agent configuration centrally from the manager.

In the Wazuh dashboard (`https://localhost:8443`):
1. Navigate to **Server Management → Endpoint Groups**
2. Click **Add new group**, name it `k8s-nodes`
3. Edit the group configuration (`agent.conf`) and add:

```xml
<agent_config>
  <localfile>
    <log_format>json</log_format>
    <location>/host/var/run/cilium/tetragon/tetragon.log</location>
  </localfile>
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <directories>/host/etc,/host/usr/bin,/host/usr/sbin</directories>
    <directories>/host/bin,/host/sbin,/host/boot</directories>
    <ignore>/host/etc/mtab</ignore>
    <ignore>/host/etc/hosts.deny</ignore>
    <ignore>/host/etc/random-seed</ignore>
    <ignore>/host/etc/adjtime</ignore>
    <ignore type="sregex">.log$|.swp$</ignore>
    <nodiff>/host/etc/ssl/private.key</nodiff>
    <skip_nfs>yes</skip_nfs>
    <skip_dev>yes</skip_dev>
    <skip_proc>yes</skip_proc>
    <skip_sys>yes</skip_sys>
    <process_priority>10</process_priority>
    <max_eps>50</max_eps>
    <synchronization>
      <enabled>yes</enabled>
      <interval>5m</interval>
      <max_eps>10</max_eps>
    </synchronization>
  </syscheck>
</agent_config>
```

> This configures Tetragon log forwarding and host filesystem integrity monitoring for all agents in the group. The `/host/` prefix maps to the host filesystem via the agent's volume mounts (configured in Step 16).

---

## Step 16 — Build the Wazuh Agent Image

The Wazuh agent DaemonSet uses a **custom Docker image** that includes the Wazuh agent binary, Python dependencies for Active Response, and the pod-deletion script. This approach is simpler and more reliable than the multi-init-container pattern — a single startup script handles configuration and launch.

### 16.1 — Create the agent build directory

```bash
mkdir -p ~/K8s/wazuh-agent-image && cd ~/K8s/wazuh-agent-image
```

### 16.2 — Create the Active Response script

This script is executed by the Wazuh agent when the manager triggers an Active Response. It uses the Kubernetes API (via in-cluster credentials from the ServiceAccount) to delete the offending pod identified in the Tetragon event.

```bash
cat <<'PYEOF' > delete-pod.py
#!/usr/bin/python3
import os
import sys
import json
import datetime
from pathlib import PureWindowsPath, PurePosixPath

try:
    import kubernetes
except ImportError:
    pass

if os.name == 'nt':
    LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"

ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3

OS_SUCCESS = 0
OS_INVALID = -1


class message:
    def __init__(self):
        self.alert = ""
        self.command = 0


def write_debug_file(ar_name, msg):
    with open(LOG_FILE, mode="a") as log_file:
        ar_name_posix = str(PurePosixPath(PureWindowsPath(
            ar_name[ar_name.find("active-response"):])))
        log_file.write(
            str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S'))
            + " " + ar_name_posix + ": " + msg + "\n")


def setup_and_check_message(argv):
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        message.command = OS_INVALID
        return message

    message.alert = data

    command = data.get("command")

    if command == "add":
        message.command = ADD_COMMAND
    elif command == "delete":
        message.command = DELETE_COMMAND
    else:
        message.command = OS_INVALID
        write_debug_file(argv[0], 'Not valid command: ' + command)

    return message


def send_keys_and_check_message(argv, keys):
    keys_msg = json.dumps({
        "version": 1,
        "origin": {"name": argv[0], "module": "active-response"},
        "command": "check_keys",
        "parameters": {"keys": keys}
    })

    write_debug_file(argv[0], keys_msg)
    print(keys_msg)
    sys.stdout.flush()

    input_str = ""
    while True:
        line = sys.stdin.readline()
        if line:
            input_str = line
            break

    write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        return message

    action = data.get("command")

    if "continue" == action:
        ret = CONTINUE_COMMAND
    elif "abort" == action:
        ret = ABORT_COMMAND
    else:
        ret = OS_INVALID
        write_debug_file(argv[0], "Invalid value of 'command'")

    return ret


def main(argv):
    write_debug_file(argv[0], "Started")

    msg = setup_and_check_message(argv)

    if msg.command < 0:
        sys.exit(OS_INVALID)

    if msg.command == ADD_COMMAND:
        alert = msg.alert["parameters"]["alert"]
        keys = [alert["rule"]["id"]]

        # Extract pod name and namespace from the Tetragon event
        pod = alert["data"]["process_exec"]["process"]["pod"]["name"]
        namespace = alert["data"]["process_exec"]["process"]["pod"]["namespace"]

        try:
            kubernetes.config.load_incluster_config()
            write_debug_file(argv[0], "Using in-cluster config")
            write_debug_file(argv[0], f"Deleting pod: {namespace}/{pod}")

            api = kubernetes.client.CoreV1Api()
            api.delete_namespaced_pod(namespace=namespace, name=pod)
            write_debug_file(argv[0], f"Pod {namespace}/{pod} deleted successfully")
        except kubernetes.config.ConfigException:
            write_debug_file(argv[0], "Failed to load in-cluster config")
        except Exception as e:
            write_debug_file(argv[0], f"Error deleting pod: {str(e)}")

    elif msg.command == DELETE_COMMAND:
        pass

    else:
        write_debug_file(argv[0], "Invalid command")

    write_debug_file(argv[0], "Ended")
    sys.exit(OS_SUCCESS)


if __name__ == "__main__":
    main(sys.argv)
PYEOF
```

### 16.3 — Create the Dockerfile

```bash
cat <<'DEOF' > Dockerfile
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && \
    apt-get install -y curl procps gnupg apt-transport-https lsb-release && \
    rm -rf /var/lib/apt/lists/*

# Install Wazuh agent
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    WAZUH_MANAGER="placeholder" apt-get install -y wazuh-agent=4.14.1-1 && \
    rm -rf /var/lib/apt/lists/*

# Install Python packages for Active Response
RUN python3 -m ensurepip 2>/dev/null || apt-get update && apt-get install -y python3-pip && \
    pip3 install requests kubernetes --break-system-packages 2>/dev/null || \
    pip3 install requests kubernetes

# Install Active Response script
COPY delete-pod.py /var/ossec/active-response/bin/delete-pod.py
RUN chmod 750 /var/ossec/active-response/bin/delete-pod.py && \
    chown root:wazuh /var/ossec/active-response/bin/delete-pod.py

ENTRYPOINT ["/bin/bash"]
DEOF
```

### 16.4 — Build and load the image into kind

```bash
docker build -t wazuh-agent-local:4.14.1 .
kind load docker-image wazuh-agent-local:4.14.1 --name security-lab
```

Verify the image is available in the cluster:
```bash
docker exec security-lab-worker crictl images | grep wazuh-agent-local
```

---

## Step 17 — Deploy Wazuh Agent DaemonSet

The Wazuh agent DaemonSet runs one agent per cluster node (3 total: control-plane + 2 workers). Each agent registers with the Wazuh manager, reads the Tetragon log from the host filesystem, and forwards events to the manager for analysis.

### 17.1 — Create the agent ConfigMap

This ConfigMap contains three files: the startup script, the ossec.conf configuration, and the deregistration script.

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: wazuh-agent-scripts
  namespace: wazuh
data:
  script.sh: |
    #!/bin/bash
    set -e
    echo "[startup] Configuring Wazuh agent..."

    # Read authd password from mounted secret file
    # (The wazuh-authd-pass secret key is "authd.pass" which contains a dot,
    #  making it invalid as a Linux environment variable name. Kubernetes
    #  envFrom silently skips such keys, so we mount the secret as a file instead.)
    if [ -f /secret/authd.pass ]; then
      cat /secret/authd.pass | tr -d '\n' > /var/ossec/etc/authd.pass
      echo "[startup] Password loaded from mounted secret"
    else
      echo "[startup] WARNING: /secret/authd.pass not found!"
    fi
    # wazuh-agentd drops privileges to the "wazuh" group — file must be group-readable
    chown root:wazuh /var/ossec/etc/authd.pass 2>/dev/null || chown root:ossec /var/ossec/etc/authd.pass
    chmod 640 /var/ossec/etc/authd.pass

    # Copy ossec.conf from ConfigMap mount
    cp /scripts/ossec.conf /var/ossec/etc/ossec.conf

    # Clean stale PID/lock files from previous runs
    rm -f /var/ossec/var/run/*.pid 2>/dev/null || true
    rm -f /var/ossec/queue/ossec/*.lock 2>/dev/null || true

    echo "[startup] Starting Wazuh agent..."
    /var/ossec/bin/wazuh-control start

    # Keep container alive and stream logs
    tail -f /var/ossec/logs/ossec.log

  deregister.py: |
    #!/usr/bin/python3
    """Deregister this agent from the Wazuh manager on pod termination."""
    import requests
    import os
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    username = os.getenv("username", "wazuh-wui")
    password = os.getenv("password", "")
    server_ip = os.getenv("WAZUH_SERVICE_HOST",
                          "wazuh.wazuh.svc.cluster.local")
    hostname = os.getenv("HOSTNAME", "")

    def login():
        try:
            resp = requests.post(
                f"https://{server_ip}:55000/security/user/authenticate?raw=true",
                verify=False,
                auth=(username, password),
                timeout=10)
            return resp.content.decode('utf-8') if resp.status_code == 200 else None
        except Exception as e:
            print(f"Login failed: {e}")
            return None

    def find_and_delete():
        token = login()
        if not token:
            print("Could not authenticate with Wazuh API")
            return

        headers = {"Authorization": f"Bearer {token}"}
        try:
            resp = requests.get(
                f"https://{server_ip}:55000/agents?pretty=true&sort=name",
                verify=False, headers=headers, timeout=10)
            agents = resp.json().get('data', {}).get('affected_items', [])
            for agent in agents:
                if agent.get('name') == hostname:
                    agent_id = agent['id']
                    print(f"Deregistering agent {hostname} (ID: {agent_id})")
                    requests.delete(
                        f"https://{server_ip}:55000/agents?"
                        f"pretty=true&older_than=0s&agents_list={agent_id}&status=all",
                        verify=False, headers=headers, timeout=10)
                    print(f"Agent {agent_id} deregistered")
                    return
            print(f"Agent {hostname} not found in manager")
        except Exception as e:
            print(f"Deregistration failed: {e}")

    if __name__ == "__main__":
        find_and_delete()

  ossec.conf: |
    <ossec_config>
      <client>
        <server>
          <address>wazuh-workers.wazuh.svc.cluster.local</address>
          <port>1514</port>
          <protocol>tcp</protocol>
        </server>
        <config-profile>ubuntu, ubuntu22, ubuntu22.04</config-profile>
        <notify_time>10</notify_time>
        <time-reconnect>60</time-reconnect>
        <auto_restart>yes</auto_restart>
        <crypto_method>aes</crypto_method>
        <enrollment>
          <manager_address>wazuh.wazuh.svc.cluster.local</manager_address>
          <enabled>yes</enabled>
          <groups>k8s-nodes</groups>
          <authorization_pass_path>etc/authd.pass</authorization_pass_path>
        </enrollment>
      </client>

      <client_buffer>
        <disabled>no</disabled>
        <queue_size>5000</queue_size>
        <events_per_second>500</events_per_second>
      </client_buffer>

      <!-- Collect Tetragon eBPF events as JSON -->
      <localfile>
        <log_format>json</log_format>
        <location>/host/var/run/cilium/tetragon/tetragon.log</location>
      </localfile>

      <!-- Basic syslog collection -->
      <localfile>
        <log_format>syslog</log_format>
        <location>/var/log/syslog</location>
      </localfile>

      <!-- System commands -->
      <localfile>
        <log_format>command</log_format>
        <command>df -P</command>
        <frequency>360</frequency>
      </localfile>

      <localfile>
        <log_format>full_command</log_format>
        <command>netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\(.*\):\([[:digit:]]*\)\ \+\([0-9\.\:\*]\+\).\+\ \([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 == \3 == \4 \5/' | sort -k 4 -g | sed 's/ == \(.*\) ==/:\1/' | sed 1,2d</command>
        <alias>netstat listening ports</alias>
        <frequency>360</frequency>
      </localfile>

      <localfile>
        <log_format>full_command</log_format>
        <command>last -n 20</command>
        <frequency>360</frequency>
      </localfile>

      <!-- Active Response -->
      <active-response>
        <disabled>no</disabled>
        <ca_store>etc/wpk_root.pem</ca_store>
        <ca_verification>yes</ca_verification>
      </active-response>

      <!-- Policy monitoring -->
      <rootcheck>
        <disabled>no</disabled>
        <check_files>yes</check_files>
        <check_trojans>yes</check_trojans>
        <check_dev>yes</check_dev>
        <check_sys>yes</check_sys>
        <check_pids>yes</check_pids>
        <check_ports>yes</check_ports>
        <check_if>yes</check_if>
        <frequency>43200</frequency>
        <rootkit_files>etc/shared/rootkit_files.txt</rootkit_files>
        <rootkit_trojans>etc/shared/rootkit_trojans.txt</rootkit_trojans>
        <skip_nfs>yes</skip_nfs>
        <ignore>/var/lib/containerd</ignore>
        <ignore>/var/lib/docker/overlay2</ignore>
      </rootcheck>

      <!-- System inventory -->
      <wodle name="syscollector">
        <disabled>no</disabled>
        <interval>1h</interval>
        <scan_on_start>yes</scan_on_start>
        <hardware>yes</hardware>
        <os>yes</os>
        <network>yes</network>
        <packages>yes</packages>
        <ports all="no">yes</ports>
        <processes>yes</processes>
        <synchronization>
          <max_eps>10</max_eps>
        </synchronization>
      </wodle>

      <!-- File integrity monitoring (disabled — use group config instead) -->
      <syscheck>
        <disabled>yes</disabled>
      </syscheck>

      <sca>
        <enabled>yes</enabled>
        <scan_on_start>yes</scan_on_start>
        <interval>12h</interval>
        <skip_nfs>yes</skip_nfs>
      </sca>

      <logging>
        <log_format>plain</log_format>
      </logging>
    </ossec_config>

    <ossec_config>
      <localfile>
        <log_format>syslog</log_format>
        <location>/var/ossec/logs/active-responses.log</location>
      </localfile>
    </ossec_config>
EOF
```

### 17.2 — Create the ServiceAccount with cluster-admin privileges

The agent needs elevated permissions to delete pods via Active Response:

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: wazuh-agent-sa
  namespace: wazuh
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: wazuh-agent-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: wazuh-agent-sa
  namespace: wazuh
EOF
```

> **Security note:** `cluster-admin` is used here for lab simplicity. In production, scope this to only the `delete pods` verb on the target namespaces.

### 17.3 — Deploy the DaemonSet

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: wazuh-agent
  namespace: wazuh
  labels:
    app: wazuh-agent
spec:
  selector:
    matchLabels:
      app: wazuh-agent
  template:
    metadata:
      labels:
        app: wazuh-agent
    spec:
      serviceAccountName: wazuh-agent-sa
      hostNetwork: true
      hostPID: true
      dnsPolicy: ClusterFirstWithHostNet
      terminationGracePeriodSeconds: 30
      containers:
      - name: wazuh-agent
        image: wazuh-agent-local:4.14.1
        imagePullPolicy: Never
        command: ["/bin/bash", "/scripts/script.sh"]
        envFrom:
        - secretRef:
            name: wazuh-api-cred
        securityContext:
          privileged: true
        resources:
          requests:
            cpu: 100m
            memory: 256Mi
          limits:
            cpu: 500m
            memory: 512Mi
        volumeMounts:
        - name: scripts
          mountPath: /scripts
        - name: authd-secret
          mountPath: /secret
          readOnly: true
        - name: var-run
          mountPath: /host/var/run
          readOnly: true
        - name: var-log
          mountPath: /host/var/log
          readOnly: true
        - name: etc
          mountPath: /host/etc
          readOnly: true
        - name: sys
          mountPath: /host/sys
          readOnly: true
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: boot
          mountPath: /host/boot
          readOnly: true
        - name: modules
          mountPath: /host/lib/modules
          readOnly: true
      volumes:
      - name: scripts
        configMap:
          name: wazuh-agent-scripts
      - name: authd-secret
        secret:
          secretName: wazuh-authd-pass
      - name: var-run
        hostPath:
          path: /var/run
      - name: var-log
        hostPath:
          path: /var/log
      - name: etc
        hostPath:
          path: /etc
      - name: sys
        hostPath:
          path: /sys
      - name: proc
        hostPath:
          path: /proc
      - name: boot
        hostPath:
          path: /boot
      - name: modules
        hostPath:
          path: /lib/modules
EOF
```

**Key design decisions in this DaemonSet:**

| Setting | Why |
|---------|-----|
| `hostNetwork: true` | Agent reports with the node's hostname, matching Tetragon events |
| `hostPID: true` | Agent can see host processes for rootcheck and syscollector |
| `dnsPolicy: ClusterFirstWithHostNet` | Resolves cluster DNS (e.g., `wazuh.wazuh.svc`) even with hostNetwork |
| `privileged: true` | Required for host filesystem access and active response |
| `imagePullPolicy: Never` | Image was loaded via `kind load`, not from a registry |
| `authd-secret` volume mount | Mounts `wazuh-authd-pass` secret as a file at `/secret/authd.pass` — see note below |
| `envFrom` (wazuh-api-cred only) | Injects API credentials for the deregistration script |
| Comprehensive host mounts | `/var/run` (Tetragon log), `/etc`, `/var/log`, `/proc`, `/sys`, `/boot`, `/lib/modules` |

> **Why mount `authd-pass` as a file instead of using `envFrom`?** The `wazuh-authd-pass` secret has a key named `authd.pass` (with a dot). Dots are not valid in Linux environment variable names, so Kubernetes `envFrom` silently skips the key — resulting in an empty password file and enrollment failures with `"No authentication password provided"`. Mounting the secret as a volume at `/secret/` avoids this entirely.
>
> **Why no `preStop` lifecycle hook?** During DaemonSet rolling updates, the old pod's `preStop` hook fires *after* the new pod has already enrolled. The deregistration script deletes the agent entry that the new pod just created, causing a permanent enrollment/connection failure loop. If you need deregistration (e.g., for cluster teardown), run the deregister script manually or use a Job instead.

### 17.4 — Watch agents start up

```bash
kubectl get pods -n wazuh -l app=wazuh-agent -w
```

Each pod should reach `Running` within 30–60 seconds. Check the agent logs:
```bash
# Pick any agent pod
AGENT_POD=$(kubectl -n wazuh get pods -l app=wazuh-agent -o name | head -n1)
kubectl logs -n wazuh ${AGENT_POD}
```

Look for:
```
[startup] Starting Wazuh agent...
Started wazuh-agentd...
Started wazuh-execd...
Started wazuh-modulesd...
Started wazuh-logcollector...
Started wazuh-syscheckd...
```

### 17.5 — Verify agents registered in Wazuh

```bash
# Check manager logs for successful registrations
kubectl logs wazuh-manager-master-0 -n wazuh | grep "New agent" | tail -10

# List all registered agents
kubectl exec -it wazuh-manager-master-0 -n wazuh -- \
  /var/ossec/bin/manage_agents -l
```

You should see three agents — one per cluster node (named after the node hostnames).

---

## Step 18 — Verify End-to-End Integration

### 18.1 — Open three terminals

**Terminal 1 — live Wazuh alert stream:**
```bash
kubectl exec -it wazuh-manager-master-0 -n wazuh -- \
  tail -f /var/ossec/logs/alerts/alerts.json | \
  python3 -c "import sys, json; [print(json.dumps(json.loads(l), indent=2)) for l in sys.stdin]"
```

**Terminal 2 — live Tetragon compact view:**
```bash
POD=$(kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon -o name | head -n1)
kubectl exec -n kube-system ${POD} -c tetragon -- \
  tetra getevents -o compact --namespace vulnerable-apps
```

**Terminal 3 — trigger test events:**
```bash
kubectl exec -it test-shell -n vulnerable-apps -- bash
```

Inside the pod, run each command and watch terminals 1 and 2 respond:

```bash
cat /etc/shadow          # → rule 700007 (sensitive file access)
curl https://example.com # → rule 700005 + 700011 (curl, namespace-aware)
apt list 2>/dev/null     # → rule 700006 (package manager)
sudo id                  # → rule 700008 (privilege escalation tool)
# The exec into this pod above already triggered → rule 700004 + 700010 (shell in container)
```

### 18.2 — Test Active Response (pod deletion)

To test the Active Response mechanism, deploy a temporary test pod and trigger rule 700005:

```bash
# Deploy a test pod
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ar-test
  namespace: vulnerable-apps
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ar-test
  template:
    metadata:
      labels:
        app: ar-test
    spec:
      containers:
      - name: shell
        image: ubuntu:22.04
        command: ["/bin/sleep", "infinity"]
EOF

# Wait for it to be ready
kubectl wait --for=condition=ready pod -l app=ar-test -n vulnerable-apps --timeout=60s

# Exec in and trigger rule 700005
kubectl exec -it deploy/ar-test -n vulnerable-apps -- bash -c "curl https://example.com"
```

Watch the Wazuh alert stream (Terminal 1). You should see:
1. Rule 700005 fires (curl detected)
2. The Active Response triggers `delete-pod.py`
3. The pod is terminated (since it's a Deployment, a new pod spins up)

Check the Active Response logs on the agent:
```bash
AGENT_POD=$(kubectl -n wazuh get pods -l app=wazuh-agent -o name | head -n1)
kubectl exec -n wazuh ${AGENT_POD} -- \
  tail -20 /var/ossec/logs/active-responses.log
```

Clean up:
```bash
kubectl delete deployment ar-test -n vulnerable-apps
```

### 18.3 — Confirm alerts in the Wazuh dashboard

With `kubectl port-forward svc/dashboard -n wazuh 8443:443` running, open `https://localhost:8443`:

1. Navigate to **Threat Intelligence → Threat Hunting → Events**
2. Filter `rule.groups: "tetragon"` — shows all Tetragon-sourced alerts
3. Filter `rule.id: 700010` — shows shell-in-vulnerable-apps alerts specifically
4. Click any alert row to expand the full Tetragon JSON payload including pod name, namespace, binary path, parent process, and UID

---

## Step 19 — Tetragon Enforcement Policies (SIGKILL)

Tetragon can go beyond observability and actively **enforce** security policy at the kernel level. Using the `Sigkill` action in a TracingPolicy, Tetragon sends SIGKILL to a process before it completes execution — the offending action never succeeds. This is fundamentally different from the Wazuh Active Response approach (Step 18), which detects events after the fact and then deletes the pod.

### 19.1 — How enforcement works

Tetragon supports three enforcement actions in TracingPolicy selectors:

| Action | Effect |
|--------|--------|
| `Sigkill` | Sends SIGKILL to the process immediately in-kernel — the process is terminated before the hooked operation completes |
| `Signal` | Sends a configurable signal (via `argSig`) to the process |
| `Override` | Overrides the return value of the function (requires `CONFIG_BPF_KPROBE_OVERRIDE` in the kernel) |

The `Sigkill` action is the most commonly used for enforcement. Because it executes in the eBPF program inside the kernel, there is no race condition — the process cannot complete the blocked operation.

### 19.2 — Verify TracingPolicy CRDs are available

The Tetragon Helm chart (installed in Step 10) deploys an operator that registers the TracingPolicy CRDs. Verify they exist:

```bash
kubectl get crd | grep cilium
```

Expected output:
```
tracingpolicies.cilium.io             <date>
tracingpoliciesnamespaced.cilium.io   <date>
```

> **Note:** The CRDs are registered under `cilium.io`, not `tetragon`. Running `kubectl get crd | grep tetragon` will return nothing — this is expected. The operator logs confirm the CRDs are installed: `kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon-operator` should show `CRD (CustomResourceDefinition) is installed and up-to-date`.

### 19.3 — Example: Kill ping in containers

This policy hooks `sys_execve` (the syscall that launches every binary) and kills any process that attempts to execute `ping` inside a container:

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: kill-ping
spec:
  kprobes:
  - call: "sys_execve"
    syscall: true
    args:
    - index: 0
      type: "string"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "/usr/bin/ping"
        - "/bin/ping"
      matchActions:
      - action: Sigkill
EOF
```

Verify the policy loaded:
```bash
kubectl get tracingpolicies
# Expected:
# NAME        AGE
# kill-ping   <age>
```

**Policy breakdown:**

| Field | Purpose |
|-------|---------|
| `call: "sys_execve"` / `syscall: true` | Hooks the execve syscall — fires every time any binary is launched |
| `args[0].type: "string"` | Captures the first argument to execve, which is the binary path |
| `matchArgs[0].operator: "Equal"` | Matches when the binary path is exactly `/usr/bin/ping` or `/bin/ping` |
| `matchActions[0].action: Sigkill` | Sends SIGKILL to the process before it starts executing |

> **Why `sys_execve` instead of `security_bprm_check`?** The `security_bprm_check` LSM hook is more elegant (it fires after binary loading but before execution), but it requires BPF LSM enabled in the kernel (`CONFIG_BPF_LSM=y` and `bpf` in the active LSM list at `/sys/kernel/security/lsm`). Many kernels — including those in kind nodes — do not have BPF LSM enabled, causing the kprobe to silently fail to attach. The `sys_execve` approach uses a standard syscall kprobe that works on any kernel with BTF support.

### 19.4 — Test the policy

```bash
# Ensure ping is installed in test-shell (if not already)
kubectl exec -it test-shell -n vulnerable-apps -- \
  bash -c "which ping || (apt-get update && apt-get install -y iputils-ping)"

# Try to ping — should be killed immediately
kubectl exec -it test-shell -n vulnerable-apps -- ping -c 1 8.8.8.8
```

Expected result: the command is terminated immediately with exit code 137 (128 + 9 = SIGKILL) or the message `Killed`.

Watch the enforcement event in Tetragon:
```bash
POD=$(kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon -o name | head -n1)
kubectl exec -n kube-system ${POD} -c tetragon -- \
  tetra getevents -o compact --namespace vulnerable-apps
```

You should see output like:
```
🚀 process vulnerable-apps/test-shell /usr/bin/ping -c 1 8.8.8.8
💥 exit    vulnerable-apps/test-shell /usr/bin/ping -c 1 8.8.8.8 SIGKILL
```

### 19.5 — Wazuh alert rule for enforcement events

The SIGKILL event appears in the Tetragon export log as a `process_exit` event. Add a Wazuh rule to generate a specific alert when Tetragon enforcement kills a process:

```bash
kubectl exec -it wazuh-manager-master-0 -n wazuh -- bash -c 'cat >> /var/ossec/etc/rules/0700-tetragon_rules.xml << '"'"'RULEEOF'"'"'

<group name="tetragon,">
  <rule id="700030" level="10">
    <decoded_as>json</decoded_as>
    <field name="process_exit.process.binary">/usr/bin/ping|/bin/ping</field>
    <field name="process_exit.signal">SIGKILL</field>
    <options>no_full_log</options>
    <group>tetragon_exit,enforcement,</group>
    <description>Tetragon enforcement: ping killed in $(process_exit.process.pod.namespace)/$(process_exit.process.pod.name)</description>
  </rule>
</group>
RULEEOF'
```

Verify syntax and restart:
```bash
kubectl exec -it wazuh-manager-master-0 -n wazuh -- /var/ossec/bin/wazuh-logtest -t
kubectl rollout restart statefulset/wazuh-manager-master -n wazuh
kubectl rollout restart statefulset/wazuh-manager-worker-0 -n wazuh
```

### 19.6 — Additional enforcement examples

**Block curl/wget (alternative to Active Response pod deletion):**
```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: kill-download-tools
spec:
  kprobes:
  - call: "sys_execve"
    syscall: true
    args:
    - index: 0
      type: "string"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "/usr/bin/curl"
        - "/bin/curl"
        - "/usr/bin/wget"
        - "/bin/wget"
      matchActions:
      - action: Sigkill
```

**Block writes to `/etc/passwd` (prevent credential tampering):**
```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: protect-etc-passwd
spec:
  kprobes:
  - call: "sys_write"
    syscall: true
    args:
    - index: 0
      type: "fd"
    - index: 1
      type: "char_buf"
      sizeArgIndex: 3
    - index: 2
      type: "size_t"
    selectors:
    - matchPIDs:
      - operator: NotIn
        followForks: true
        isNamespacePID: true
        values:
        - 0
        - 1
      matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/etc/passwd"
      matchActions:
      - action: Sigkill
```

> **Enforcement vs Active Response tradeoffs:** Tetragon enforcement (SIGKILL) kills the specific process instantly but leaves the container running. Wazuh Active Response (Step 15.2) deletes the entire pod, which is a stronger response but has higher latency (seconds vs microseconds). Both approaches are complementary — use Tetragon enforcement for immediate blocking and Active Response for broader containment.

### 19.7 — Managing enforcement policies

```bash
# List all policies
kubectl get tracingpolicies

# Inspect a specific policy
kubectl get tracingpolicy kill-ping -o yaml

# Delete a policy (immediately stops enforcement)
kubectl delete tracingpolicy kill-ping

# Check Tetragon logs for policy load errors
POD=$(kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon -o name | head -n1)
kubectl logs -n kube-system ${POD} -c tetragon | grep -i "kill-ping\|error" | tail -10
```

### Troubleshooting enforcement policies

**Policy created but enforcement doesn't trigger:**
```bash
# Verify the policy state shows no errors
kubectl get tracingpolicies kill-ping -o yaml | grep -A10 status

# Check Tetragon logs for load failures
POD=$(kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon -o name | head -n1)
kubectl logs -n kube-system ${POD} -c tetragon | grep -i "adding tracing policy\|error\|fail" | tail -10

# Watch events to see if Tetragon sees the process at all
kubectl exec -n kube-system ${POD} -c tetragon -- \
  tetra getevents -o compact --namespace vulnerable-apps
```

**`security_bprm_check` kprobe doesn't fire (common in kind):**

The LSM hook `security_bprm_check` requires BPF LSM enabled in the kernel. Check with:
```bash
docker exec security-lab-worker cat /sys/kernel/security/lsm
```
If the output does not include `bpf`, LSM-based hooks will silently fail. Use `sys_execve` (syscall kprobe) instead — it works on all kernels with BTF support.

**`/boot/config` not found errors in Tetragon logs:**

This is a non-fatal warning. Kind nodes don't expose the host kernel config at `/boot/config-*`. Tetragon still functions correctly for kprobe-based policies — it only impacts automatic kernel feature detection for advanced features like LSM hooks.


---

## Cluster Health Check

Run at any point for a full status overview:

```bash
echo "=== Cluster Info ==="
kubectl cluster-info

echo -e "\n=== Nodes ==="
kubectl get nodes -o wide

echo -e "\n=== All Pods ==="
kubectl get pods -A

echo -e "\n=== Namespaces ==="
kubectl get namespaces

echo -e "\n=== Workloads in vulnerable-apps ==="
kubectl get pods -n vulnerable-apps

echo -e "\n=== Wazuh Stack (server + agents) ==="
kubectl get pods -n wazuh

echo -e "\n=== Tetragon ==="
kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon

echo -e "\n=== Services ==="
kubectl get svc -A

echo -e "\n=== Registered Wazuh Agents ==="
kubectl exec -it wazuh-manager-master-0 -n wazuh -- \
  /var/ossec/bin/manage_agents -l 2>/dev/null | grep "Name:"

echo -e "\n=== Recent Tetragon Alerts ==="
kubectl exec -it wazuh-manager-master-0 -n wazuh -- \
  grep '"tetragon"' /var/ossec/logs/alerts/alerts.json 2>/dev/null | tail -3 | \
  python3 -c "import sys,json; [print(json.loads(l).get('rule',{}).get('description','')) for l in sys.stdin]"

echo -e "\n=== Active Response Log (last 5 entries) ==="
AGENT_POD=$(kubectl -n wazuh get pods -l app=wazuh-agent -o name 2>/dev/null | head -n1)
if [ -n "${AGENT_POD}" ]; then
  kubectl exec -n wazuh ${AGENT_POD} -- \
    tail -5 /var/ossec/logs/active-responses.log 2>/dev/null || echo "No AR log entries"
fi
```

---

## Troubleshooting

### Agents not registering (pod stays in Running but no events)
```bash
# Check agent logs
AGENT_POD=$(kubectl -n wazuh get pods -l app=wazuh-agent -o name | head -n1)
kubectl logs -n wazuh ${AGENT_POD}

# Check if authd password was written correctly
kubectl exec -n wazuh ${AGENT_POD} -- cat /var/ossec/etc/authd.pass

# Verify the secret keys match what the startup script expects
kubectl get secret wazuh-authd-pass -n wazuh -o jsonpath='{.data}' | python3 -c "
import sys, json, base64
for k,v in json.load(sys.stdin).items(): print(f'Key: {k}')"

# Verify DNS resolves the manager from the agent pod
kubectl exec -n wazuh ${AGENT_POD} -- \
  getent hosts wazuh.wazuh.svc.cluster.local

# Check agent status
kubectl exec -n wazuh ${AGENT_POD} -- /var/ossec/bin/wazuh-control status
```

> **Common issue:** The `wazuh-authd-pass` secret key name varies between Wazuh versions. The startup script tries both `authd` and `authd.pass`. If neither works, check the actual key name with `kubectl get secret wazuh-authd-pass -n wazuh -o yaml` and update the script accordingly.

### Tetragon log file not found at host path
```bash
# Check the log exists inside the Tetragon pod
TETRAGON_POD=$(kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon -o name | head -n1)
kubectl exec -n kube-system ${TETRAGON_POD} -c tetragon -- \
  ls -la /var/run/cilium/tetragon/

# Check if the path exists on the kind node containers directly
docker exec security-lab-worker ls /var/run/cilium/tetragon/ 2>/dev/null || \
  echo "Not found on worker node — check Tetragon ConfigMap (Step 14.2)"

# Verify the agent can see the file via its mount
AGENT_POD=$(kubectl -n wazuh get pods -l app=wazuh-agent -o name | head -n1)
kubectl exec -n wazuh ${AGENT_POD} -- \
  ls -la /host/var/run/cilium/tetragon/
```

### Wazuh indexer pods stuck in Init
The OpenSearch indexer requires `vm.max_map_count=262144`. Set it on each kind node:
```bash
for node in $(kubectl get nodes -o name | sed 's|node/||'); do
  docker exec ${node} sysctl -w vm.max_map_count=262144
done
```

### Dashboard shows ERROR3099 — `wazuh-modulesd->failed`
The Wazuh dashboard refuses API connections with `ERROR3099 - Some Wazuh daemons are not ready yet in node "wazuh-manager-master" (wazuh-modulesd->failed)`. This typically means `wazuh-modulesd` crashed during startup.

Check the manager logs for the root cause:
```bash
kubectl exec -it wazuh-manager-master-0 -n wazuh -- \
  grep -iE "CRITICAL|modulesd.*ERROR" /var/ossec/logs/ossec.log | tail -10
```

**Most common cause:** `Couldn't init inotify: Too many open files`. The combined inotify pressure from Kubernetes controllers, Tetragon, and Wazuh exceeds the default Linux limit. Fix by raising limits on the host (kind nodes share the host kernel):

```bash
sudo sysctl -w fs.inotify.max_user_watches=524288
sudo sysctl -w fs.inotify.max_user_instances=512

# Make permanent
echo "fs.inotify.max_user_watches=524288" | sudo tee -a /etc/sysctl.conf
echo "fs.inotify.max_user_instances=512" | sudo tee -a /etc/sysctl.conf
```

Then restart the manager and verify all daemons recover:
```bash
kubectl exec -it wazuh-manager-master-0 -n wazuh -- /var/ossec/bin/wazuh-control restart
# Wait ~30 seconds
kubectl exec -it wazuh-manager-master-0 -n wazuh -- /var/ossec/bin/wazuh-control status
```

> See Step 6.1 for the recommended preventive setup during cluster creation.

### StorageClass "wazuh-storage" is invalid: provisioner: Required value
The `wazuh-kubernetes` repo ships with the provisioner commented out in `wazuh/base/storage-class.yaml`. Kustomize patches cannot add a field that is absent in the base.

```bash
# Check what provisioner your cluster uses
kubectl get sc

# Edit the base file directly (not the overlay patch)
cat <<'EOF' > wazuh/base/storage-class.yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: wazuh-storage
provisioner: rancher.io/local-path
reclaimPolicy: Delete
volumeBindingMode: WaitForFirstConsumer
EOF

# Verify kustomize renders it correctly
kubectl kustomize envs/local-env/ | grep -A5 "kind: StorageClass"
```

Also check that `envs/local-env/kustomization.yml` has only **one** `patches:` block. YAML silently discards all but the last duplicate key, so multiple `patches:` blocks cause earlier patches to be ignored.

### Namespace stuck in Terminating after failed deploy
If you delete and immediately re-apply, the namespace may still be terminating:
```bash
# Watch until the namespace fully disappears
kubectl get ns wazuh -w

# If stuck, check what resources are blocking deletion
kubectl get all -n wazuh
kubectl get pvc -n wazuh

# Only re-apply after the namespace is gone
kubectl apply -k envs/local-env/
```

### Custom rules not firing
Use `wazuh-logtest` to test a raw Tetragon JSON line interactively:
```bash
TETRAGON_POD=$(kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon -o name | head -n1)

# Grab a real log line
kubectl exec -n kube-system ${TETRAGON_POD} -c tetragon -- \
  tail -n 1 /var/run/cilium/tetragon/tetragon.log

# Paste it into the interactive tester
kubectl exec -it wazuh-manager-master-0 -n wazuh -- \
  /var/ossec/bin/wazuh-logtest
```

### Active Response not executing
```bash
# Check AR is enabled on the manager
kubectl exec -it wazuh-manager-master-0 -n wazuh -- \
  grep -A5 "active-response" /var/ossec/etc/ossec.conf

# Check the AR script exists on the agent
AGENT_POD=$(kubectl -n wazuh get pods -l app=wazuh-agent -o name | head -n1)
kubectl exec -n wazuh ${AGENT_POD} -- \
  ls -la /var/ossec/active-response/bin/delete-pod.py

# Check AR logs on the agent
kubectl exec -n wazuh ${AGENT_POD} -- \
  cat /var/ossec/logs/active-responses.log
```

### Agent deregistration not working on pod termination
```bash
# Manually test the deregister script
AGENT_POD=$(kubectl -n wazuh get pods -l app=wazuh-agent -o name | head -n1)
kubectl exec -n wazuh ${AGENT_POD} -- python3 /scripts/deregister.py

# Check if the wazuh-api-cred secret has the expected keys
kubectl get secret wazuh-api-cred -n wazuh -o jsonpath='{.data}' | python3 -c "
import sys, json, base64
for k,v in json.load(sys.stdin).items(): print(f'Key: {k} = {base64.b64decode(v).decode()}')"
```

---

## Teardown

```bash
# Delete the kind cluster (removes everything)
kind delete cluster --name security-lab

# Clean up host directories
rm -rf /tmp/kind-security-lab /tmp/wazuh-agent-ossec

# Clean up the agent image
docker rmi wazuh-agent-local:4.14.1 2>/dev/null
```

---

## Summary of All Components

| Component | Namespace | Kind | Purpose |
|-----------|-----------|------|---------|
| `tetragon` | `kube-system` | DaemonSet | eBPF kernel event capture on every node |
| `wazuh-manager-master` | `wazuh` | StatefulSet | SIEM core: rules engine, agent auth, API, Active Response |
| `wazuh-manager-worker-0` | `wazuh` | StatefulSet | Agent event ingestion worker |
| `wazuh-indexer-0` | `wazuh` | StatefulSet | OpenSearch — stores and indexes all alerts |
| `wazuh-dashboard` | `wazuh` | Deployment | Web UI for alert triage and rule management |
| `wazuh-agent` | `wazuh` | DaemonSet | 1 agent per node — reads Tetragon log, reports to manager, runs AR |
| `test-shell` | `vulnerable-apps` | Pod | Ubuntu shell for triggering test events |
| `test-nginx` | `vulnerable-apps` | Pod | Nginx with exposed sensitive ConfigMap |
| `test-privileged` | `vulnerable-apps` | Pod | Privileged container with host root mount |
| `test-network` | `vulnerable-apps` | Pod | Network tools container (netshoot) |
| `vulnerable-webapp` | `vulnerable-apps` | Deployment | DVWA exposed on NodePort 30000 |

## Key File Paths

| Path | Where | Description |
|------|-------|-------------|
| `/var/run/cilium/tetragon/tetragon.log` | Each node host filesystem | Tetragon eBPF event stream (JSON per line) |
| `/host/var/run/cilium/tetragon/tetragon.log` | Inside wazuh-agent pod | Same file, accessed via hostPath mount |
| `/var/ossec/etc/rules/0700-tetragon_rules.xml` | wazuh-manager-master-0 | Custom Tetragon detection rules |
| `/var/ossec/logs/alerts/alerts.json` | wazuh-manager-master-0 | All fired alert records |
| `/var/ossec/active-response/bin/delete-pod.py` | wazuh-agent pods | Active Response script for pod deletion |
| `/var/ossec/logs/active-responses.log` | wazuh-agent pods | Active Response execution log |
| `/var/ossec/etc/ossec.conf` | wazuh-agent pods (via ConfigMap) | Agent config including localfile stanza |
| `~/K8s/kind-security-cluster.yaml` | Host machine | Kind cluster definition |
| `~/K8s/wazuh-kubernetes/` | Host machine | Wazuh Kustomize manifests |
| `~/K8s/wazuh-agent-image/` | Host machine | Custom agent Docker image build context |

---

## Summary of Changes from Original Guide

| # | Original Issue | Fix Applied |
|---|---|---|
| 1 | Agent used fragile 4-step init container chain | Replaced with single ConfigMap startup script |
| 2 | Agent ran in separate `wazuh-agents` namespace | Moved to `wazuh` namespace — shares secrets and network context |
| 3 | Agent used official Docker image with incompatible entrypoint | Custom image built locally with `wazuh-agent` package + AR deps |
| 4 | No `hostNetwork` or `hostPID` | Added both — agent sees host processes and uses node hostname |
| 5 | `preStop` deregistration hook races with rolling updates | Removed `preStop` hook — old pod's deregister script deletes the agent entry the new pod just created, causing permanent enrollment failure |
| 6 | No Active Response capability | Added `delete-pod.py` AR script + manager AR config |
| 7 | Only mounted Tetragon log directory | Comprehensive host mounts: `/etc`, `/var/log`, `/proc`, `/sys`, `/boot`, `/lib/modules` |
| 8 | `ossec-data` stored on volatile `/tmp` hostPath | Agent state managed within container; ConfigMap provides reproducible config |
| 9 | No agent group management | Added `k8s-nodes` group with centralized agent config from dashboard |
| 10 | `dnsPolicy` not set with `hostNetwork` | Added `dnsPolicy: ClusterFirstWithHostNet` for cluster DNS resolution |
| 11 | Wazuh `LoadBalancer` services hang in kind | Patched all services to `ClusterIP`; dashboard via `port-forward` |
| 12 | Tetragon log path inconsistencies | Standardized all paths to `/var/run/cilium/tetragon/tetragon.log` |
| 13 | StorageClass provisioner commented out in base manifest | Set `rancher.io/local-path` directly in `wazuh/base/storage-class.yaml` for kind |
| 14 | Appending `patches:` to kustomization.yml creates duplicate keys | Consolidated into single `patches:` block written in one step |
| 15 | Default inotify limits too low for combined stack | Raised `max_user_watches` and `max_user_instances` on host (Step 6.1) — prevents `wazuh-modulesd` crash and ERROR3099 |
| 16 | Manager resource limits too low (400m CPU / 512Mi) | Increased to 2 CPU / 2Gi in base StatefulSet files (Step 13.6) — prevents manager CPU saturation and agent connection drops |
| 17 | `authd.pass` secret key skipped by `envFrom` (dot in name) | Mounted `wazuh-authd-pass` as a volume file at `/secret/authd.pass` instead of injecting via environment variables |
| 18 | `authd.pass` file owned by `root:root` with 640 permissions | Added `chown root:wazuh` in startup script — `wazuh-agentd` drops to `wazuh` group and needs group-read access |