#!/usr/bin/env bash
# Tetragon + Wazuh security lab bootstrap.
# Run as root: sudo bash bootstrap.sh
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "ERROR: must run as root. Try: sudo bash $0" >&2
  exit 1
fi

REAL_USER="${SUDO_USER:-ubuntu}"
REAL_HOME=$(eval echo "~${REAL_USER}")
LAB_DIR="${REAL_HOME}/K8s"
LOG="${REAL_HOME}/bootstrap.log"

export DEBIAN_FRONTEND=noninteractive
export KUBECONFIG=/root/.kube/config

mkdir -p "$LAB_DIR"

phase() { echo -e "\n========== [$(date +%H:%M:%S)] $1 ==========\n"; }
wait_pod_running() {
  local ns="$1" sel="$2" timeout="${3:-300}"
  kubectl wait --for=condition=ready pod -l "$sel" -n "$ns" --timeout="${timeout}s" || true
}

phase "PHASE 0 — sysctl"
sysctl -w fs.inotify.max_user_watches=524288 || true
sysctl -w fs.inotify.max_user_instances=512 || true
sysctl -w vm.max_map_count=262144 || true
grep -q fs.inotify.max_user_watches /etc/sysctl.conf || {
  echo "fs.inotify.max_user_watches=524288" >> /etc/sysctl.conf
  echo "fs.inotify.max_user_instances=512" >> /etc/sysctl.conf
  echo "vm.max_map_count=262144" >> /etc/sysctl.conf
}

phase "PHASE 1 — base packages"
apt-get update -y
apt-get install -y curl wget gpg jq git python3-pip apt-transport-https ca-certificates lsb-release

phase "PHASE 2 — Docker"
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
  sh /tmp/get-docker.sh
  rm /tmp/get-docker.sh
  usermod -aG docker "$REAL_USER" || true
  systemctl enable --now docker
fi
docker ps >/dev/null

phase "PHASE 3 — kubectl"
if ! command -v kubectl >/dev/null; then
  KVER=$(curl -Ls https://dl.k8s.io/release/stable.txt)
  curl -L -o /tmp/kubectl "https://dl.k8s.io/release/${KVER}/bin/linux/amd64/kubectl"
  install -o root -g root -m 0755 /tmp/kubectl /usr/local/bin/kubectl
  rm /tmp/kubectl
fi
kubectl version --client

phase "PHASE 4 — kind"
if ! command -v kind >/dev/null; then
  curl -Lo /tmp/kind https://kind.sigs.k8s.io/dl/v0.31.0/kind-linux-amd64
  chmod +x /tmp/kind
  mv /tmp/kind /usr/local/bin/kind
fi
kind --version

phase "PHASE 5 — Helm"
if ! command -v helm >/dev/null; then
  curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi
helm version

phase "PHASE 6 — kind cluster"
mkdir -p /tmp/kind-security-lab
cat > "${LAB_DIR}/kind-security-cluster.yaml" <<'YAMLEOF'
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
YAMLEOF

if ! kind get clusters 2>/dev/null | grep -q '^security-lab$'; then
  kind create cluster --config "${LAB_DIR}/kind-security-cluster.yaml"
fi

# Ensure vm.max_map_count is set inside each kind node container too
for node in $(kubectl get nodes -o name | sed 's|node/||'); do
  docker exec "$node" sysctl -w vm.max_map_count=262144 || true
done

kubectl cluster-info --context kind-security-lab
kubectl get nodes

phase "PHASE 7 — namespaces + RBAC"
for ns in vulnerable-apps security-testing monitoring; do
  kubectl get ns "$ns" >/dev/null 2>&1 || kubectl create namespace "$ns"
done
kubectl label --overwrite namespace vulnerable-apps env=test security=monitored
kubectl label --overwrite namespace security-testing env=test security=monitored
kubectl get sa security-test-sa -n security-testing >/dev/null 2>&1 || \
  kubectl create serviceaccount security-test-sa -n security-testing

kubectl apply -f - <<'EOF'
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
kubectl get clusterrolebinding security-test-binding >/dev/null 2>&1 || \
  kubectl create clusterrolebinding security-test-binding \
    --clusterrole=security-test-role \
    --serviceaccount=security-testing:security-test-sa

phase "PHASE 8 — metrics-server"
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
kubectl patch deployment metrics-server -n kube-system --type='json' \
  -p='[{"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--kubelet-insecure-tls"}]' || true

phase "PHASE 9 — test workloads"
kubectl apply -f - <<'EOF'
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
---
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
---
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
---
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
---
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

kubectl get secret db-credentials -n vulnerable-apps >/dev/null 2>&1 || \
  kubectl create secret generic db-credentials \
    --from-literal=username=admin \
    --from-literal=password=SuperSecret123 \
    -n vulnerable-apps

kubectl get cm app-config -n vulnerable-apps >/dev/null 2>&1 || \
  kubectl create configmap app-config \
    --from-literal=api_key=sk-1234567890abcdef \
    --from-literal=database_url=postgresql://admin:password@db:5432/appdb \
    -n vulnerable-apps

phase "PHASE 10 — Tetragon"
helm repo add cilium https://helm.cilium.io 2>/dev/null || true
helm repo update
helm list -n kube-system | grep -q '^tetragon\s' || \
  helm install tetragon cilium/tetragon -n kube-system
kubectl rollout status -n kube-system ds/tetragon --timeout=300s

# Step 14.2 + 14.3: enable export file + scope to lab namespaces
kubectl patch cm tetragon-config -n kube-system --type merge -p '{
  "data": {
    "export-filename": "/var/run/cilium/tetragon/tetragon.log",
    "export-file-max-size-mb": "100",
    "export-file-rotation-interval": "24h",
    "export-allowlist": "{\"event_set\":[\"PROCESS_EXEC\",\"PROCESS_EXIT\",\"PROCESS_KPROBE\"],\"namespace\":[\"vulnerable-apps\",\"security-testing\",\"wazuh\"]}"
  }
}'
kubectl rollout restart ds/tetragon -n kube-system
kubectl rollout status ds/tetragon -n kube-system --timeout=180s

phase "PHASE 11 — Wazuh manifests (clone + patch)"
cd "$LAB_DIR"
if [ ! -d wazuh-kubernetes ]; then
  git clone https://github.com/wazuh/wazuh-kubernetes.git -b v4.14.1 --depth=1
fi
cd wazuh-kubernetes

chmod +x wazuh/certs/indexer_cluster/generate_certs.sh wazuh/certs/dashboard_http/generate_certs.sh
[ -f wazuh/certs/indexer_cluster/root-ca.pem ] || bash wazuh/certs/indexer_cluster/generate_certs.sh
[ -f wazuh/certs/dashboard_http/cert.pem ]     || bash wazuh/certs/dashboard_http/generate_certs.sh

# Fix StorageClass provisioner for kind
cat > wazuh/base/storage-class.yaml <<'EOF'
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: wazuh-storage
provisioner: rancher.io/local-path
reclaimPolicy: Delete
volumeBindingMode: WaitForFirstConsumer
EOF

# Patch services to ClusterIP
cat > envs/local-env/services-clusterip-patch.yaml <<'EOF'
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

# Consolidated kustomization
cat > envs/local-env/kustomization.yml <<'EOF'
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

# Bump manager resources
sed -i 's/cpu: 400m/cpu: "2"/; s/memory: 512Mi/memory: 2Gi/' wazuh/wazuh_managers/wazuh-master-sts.yaml
sed -i 's/cpu: 400m/cpu: "2"/; s/memory: 512Mi/memory: 2Gi/' wazuh/wazuh_managers/wazuh-worker-sts.yaml

phase "PHASE 12 — deploy Wazuh"
kubectl apply -k envs/local-env/

phase "PHASE 13 — wait for Wazuh pods (long: 5-10 min)"
kubectl rollout status statefulset/wazuh-indexer        -n wazuh --timeout=900s
kubectl rollout status statefulset/wazuh-manager-master -n wazuh --timeout=600s
kubectl rollout status statefulset/wazuh-manager-worker -n wazuh --timeout=600s
kubectl rollout status deployment/wazuh-dashboard       -n wazuh --timeout=600s

phase "PHASE 14 — install custom Tetragon rules in manager"
cat > /tmp/0700-tetragon_rules.xml <<'EOF'
<group name="tetragon,">

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

  <rule id="700003" level="5">
    <if_sid>700001</if_sid>
    <field name="process_exit.status">^[^0]</field>
    <options>no_full_log</options>
    <group>tetragon_exit,</group>
    <description>Tetragon: Process exited with non-zero status (possible crash)</description>
  </rule>

  <rule id="700004" level="8">
    <if_sid>700000</if_sid>
    <field name="process_exec.process.binary">/usr/bin/sh|/bin/sh|/usr/bin/bash|/bin/bash|/usr/bin/zsh|/bin/zsh|/usr/bin/dash</field>
    <options>no_full_log</options>
    <group>tetragon_exec,container_shell,</group>
    <description>Tetragon: Shell spawned in container - possible interactive intrusion</description>
  </rule>

  <rule id="700005" level="7">
    <if_sid>700000</if_sid>
    <field name="process_exec.process.binary">/usr/bin/curl|/bin/curl|/usr/bin/wget|/bin/wget</field>
    <options>no_full_log</options>
    <group>tetragon_exec,data_exfil,</group>
    <description>Tetragon: curl/wget executed in container</description>
  </rule>

  <rule id="700006" level="7">
    <if_sid>700000</if_sid>
    <field name="process_exec.process.binary">/usr/bin/apt|/usr/bin/apt-get|/usr/bin/dpkg|/usr/bin/yum|/usr/bin/dnf|/usr/bin/apk|/usr/bin/rpm</field>
    <options>no_full_log</options>
    <group>tetragon_exec,package_install,</group>
    <description>Tetragon: Package manager executed in container - possible unauthorized install</description>
  </rule>

  <rule id="700007" level="10">
    <if_sid>700000</if_sid>
    <field name="process_exec.process.arguments">/etc/shadow|/etc/passwd|/etc/sudoers|/root/.ssh/|/proc/</field>
    <options>no_full_log</options>
    <group>tetragon_exec,sensitive_file,</group>
    <description>Tetragon: Sensitive system file accessed</description>
  </rule>

  <rule id="700008" level="10">
    <if_sid>700000</if_sid>
    <field name="process_exec.process.binary">/usr/bin/sudo|/bin/su|/usr/bin/su|/usr/sbin/usermod|/usr/sbin/useradd</field>
    <options>no_full_log</options>
    <group>tetragon_exec,priv_escalation,</group>
    <description>Tetragon: Privilege escalation tool executed - $(process_exec.process.binary)</description>
  </rule>

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

  <rule id="700020" level="6">
    <if_sid>700002</if_sid>
    <field name="process_kprobe.function_name">tcp_connect|ip4_datagram_connect</field>
    <options>no_full_log</options>
    <group>tetragon_kprobe,network,</group>
    <description>Tetragon: Outbound TCP/UDP connection at kernel level from $(process_kprobe.process.binary)</description>
  </rule>

</group>
EOF
kubectl cp /tmp/0700-tetragon_rules.xml wazuh/wazuh-manager-master-0:/var/ossec/etc/rules/0700-tetragon_rules.xml
kubectl rollout restart statefulset/wazuh-manager-master -n wazuh
kubectl rollout restart statefulset/wazuh-manager-worker -n wazuh
kubectl rollout status statefulset/wazuh-manager-master -n wazuh --timeout=300s
kubectl rollout status statefulset/wazuh-manager-worker -n wazuh --timeout=300s

phase "PHASE 15 — build agent image"
AGENT_DIR="${LAB_DIR}/wazuh-agent-image"
mkdir -p "$AGENT_DIR"

cat > "${AGENT_DIR}/delete-pod.py" <<'PYEOF'
#!/usr/bin/python3
import os, sys, json, datetime
from pathlib import PureWindowsPath, PurePosixPath
try:
    import kubernetes
except ImportError:
    pass
LOG_FILE = "/var/ossec/logs/active-responses.log"
ADD_COMMAND, DELETE_COMMAND, CONTINUE_COMMAND, ABORT_COMMAND = 0,1,2,3
OS_SUCCESS, OS_INVALID = 0, -1
class message:
    def __init__(self):
        self.alert = ""
        self.command = 0
def write_debug_file(ar_name, msg):
    with open(LOG_FILE, mode="a") as f:
        ar_name_posix = str(PurePosixPath(PureWindowsPath(ar_name[ar_name.find("active-response"):])))
        f.write(str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')) + " " + ar_name_posix + ": " + msg + "\n")
def setup_and_check_message(argv):
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break
    write_debug_file(argv[0], input_str)
    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'invalid JSON')
        message.command = OS_INVALID
        return message
    message.alert = data
    cmd = data.get("command")
    if cmd == "add": message.command = ADD_COMMAND
    elif cmd == "delete": message.command = DELETE_COMMAND
    else:
        message.command = OS_INVALID
        write_debug_file(argv[0], 'bad command: ' + str(cmd))
    return message
def main(argv):
    write_debug_file(argv[0], "Started")
    msg = setup_and_check_message(argv)
    if msg.command < 0: sys.exit(OS_INVALID)
    if msg.command == ADD_COMMAND:
        alert = msg.alert["parameters"]["alert"]
        pod = alert["data"]["process_exec"]["process"]["pod"]["name"]
        ns = alert["data"]["process_exec"]["process"]["pod"]["namespace"]
        try:
            kubernetes.config.load_incluster_config()
            write_debug_file(argv[0], f"Deleting {ns}/{pod}")
            kubernetes.client.CoreV1Api().delete_namespaced_pod(namespace=ns, name=pod)
            write_debug_file(argv[0], f"OK {ns}/{pod}")
        except Exception as e:
            write_debug_file(argv[0], f"err: {e}")
    write_debug_file(argv[0], "Ended")
    sys.exit(OS_SUCCESS)
if __name__ == "__main__":
    main(sys.argv)
PYEOF

cat > "${AGENT_DIR}/Dockerfile" <<'DEOF'
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y curl procps gnupg apt-transport-https lsb-release python3-pip && \
    rm -rf /var/lib/apt/lists/*
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    WAZUH_MANAGER="placeholder" apt-get install -y wazuh-agent=4.14.1-1 && \
    rm -rf /var/lib/apt/lists/*
RUN pip3 install requests kubernetes --break-system-packages 2>/dev/null || pip3 install requests kubernetes
COPY delete-pod.py /var/ossec/active-response/bin/delete-pod.py
RUN chmod 750 /var/ossec/active-response/bin/delete-pod.py && \
    chown root:wazuh /var/ossec/active-response/bin/delete-pod.py
ENTRYPOINT ["/bin/bash"]
DEOF

cd "$AGENT_DIR"
docker build -t wazuh-agent-local:4.14.1 .
kind load docker-image wazuh-agent-local:4.14.1 --name security-lab

phase "PHASE 16 — agent ConfigMap + SA + DaemonSet"
kubectl apply -n wazuh -f - <<'EOF'
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
    if [ -f /secret/authd.pass ]; then
      cat /secret/authd.pass | tr -d '\n' > /var/ossec/etc/authd.pass
      echo "[startup] Password loaded from mounted secret"
    else
      echo "[startup] WARNING: /secret/authd.pass not found!"
    fi
    chown root:wazuh /var/ossec/etc/authd.pass 2>/dev/null || chown root:ossec /var/ossec/etc/authd.pass
    chmod 640 /var/ossec/etc/authd.pass
    cp /scripts/ossec.conf /var/ossec/etc/ossec.conf
    rm -f /var/ossec/var/run/*.pid 2>/dev/null || true
    rm -f /var/ossec/queue/ossec/*.lock 2>/dev/null || true
    echo "[startup] Starting Wazuh agent..."
    /var/ossec/bin/wazuh-control start
    tail -f /var/ossec/logs/ossec.log
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
      <localfile>
        <log_format>json</log_format>
        <location>/host/var/run/cilium/tetragon/tetragon.log</location>
      </localfile>
      <localfile>
        <log_format>syslog</log_format>
        <location>/var/log/syslog</location>
      </localfile>
      <active-response>
        <disabled>no</disabled>
        <ca_store>etc/wpk_root.pem</ca_store>
        <ca_verification>yes</ca_verification>
      </active-response>
      <rootcheck>
        <disabled>no</disabled>
        <frequency>43200</frequency>
        <skip_nfs>yes</skip_nfs>
        <ignore>/var/lib/containerd</ignore>
        <ignore>/var/lib/docker/overlay2</ignore>
      </rootcheck>
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
      </wodle>
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
---
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
---
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
        hostPath: { path: /var/run }
      - name: var-log
        hostPath: { path: /var/log }
      - name: etc
        hostPath: { path: /etc }
      - name: sys
        hostPath: { path: /sys }
      - name: proc
        hostPath: { path: /proc }
      - name: boot
        hostPath: { path: /boot }
      - name: modules
        hostPath: { path: /lib/modules }
EOF

phase "PHASE 17 — wait agents up"
kubectl rollout status ds/wazuh-agent -n wazuh --timeout=300s

phase "PHASE 18 — copy kubeconfig to user"
mkdir -p "${REAL_HOME}/.kube"
cp /root/.kube/config "${REAL_HOME}/.kube/config"
chown -R "${REAL_USER}:${REAL_USER}" "${REAL_HOME}/.kube" "$LAB_DIR"

phase "DONE"
kubectl get pods -A
echo
echo "=== Wazuh agents registered ==="
kubectl exec -n wazuh wazuh-manager-master-0 -- /var/ossec/bin/manage_agents -l 2>/dev/null | grep -E "Name:|ID:" || true
