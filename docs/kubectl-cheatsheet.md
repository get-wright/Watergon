# kubectl cheatsheet — Watergon lab

Copy-paste commands tuned to **this lab**: `security-lab` kind cluster with Tetragon + Wazuh + DVWA. All commands assume `KUBECONFIG=~/.kube/config` already set (bootstrap.sh copies kind's kubeconfig there).

> Quick mental map: `kube-system` → Tetragon. `wazuh` → manager/worker/indexer/dashboard/agent. `vulnerable-apps` → DVWA.

---

## Discovery

```bash
# Everything everywhere
kubectl get pods -A
kubectl get pods -A -o wide                 # +IP, +node
kubectl get all -n wazuh                    # one namespace, all kinds
kubectl get nodes -o wide

# Watch live
kubectl get pods -n wazuh -w

# What's NOT Running?
kubectl get pods -A --field-selector=status.phase!=Running

# By label
kubectl get pods -A -l security=monitored
kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon
kubectl get pods -n wazuh -l app=wazuh-agent

# Resources usage (needs metrics-server — bootstrap installs it)
kubectl top nodes
kubectl top pods -A --sort-by=cpu
```

---

## Inspect a single pod / deployment

```bash
kubectl describe pod wazuh-manager-master-0 -n wazuh
kubectl describe ds wazuh-agent -n wazuh
kubectl describe deploy vulnerable-webapp -n vulnerable-apps

# Full YAML (state including defaults)
kubectl get pod wazuh-indexer-0 -n wazuh -o yaml | less

# Just one field with jsonpath
kubectl get pod test-shell -n vulnerable-apps -o jsonpath='{.spec.nodeName}'
kubectl get nodes -o jsonpath='{.items[*].metadata.name}'

# Events (often where the real error lives)
kubectl get events -n wazuh --sort-by=.lastTimestamp | tail -20
kubectl get events -A --field-selector type=Warning
```

---

## Exec — run commands inside a pod

```bash
# One-shot command
kubectl exec -n wazuh wazuh-manager-master-0 -- /var/ossec/bin/manage_agents -l

# Interactive shell
kubectl exec -it -n vulnerable-apps deploy/vulnerable-webapp -- bash

# Specific container (multi-container pod, e.g. tetragon)
kubectl exec -n kube-system tetragon-abc12 -c tetragon -- tetra getevents -o compact

# Run with shell redirects
kubectl exec -n wazuh wazuh-manager-master-0 -- bash -c 'wc -l /var/ossec/logs/alerts/alerts.json'

# Pipe input to a command inside the pod
kubectl exec -i -n wazuh wazuh-manager-master-0 -- /var/ossec/bin/wazuh-logtest < /tmp/event.json
```

---

## Attach — view stdout/stderr of running container

```bash
# Attach to PID 1 of the container — see live stdout
kubectl attach -n vulnerable-apps deploy/vulnerable-webapp -i -t

# Detach: Ctrl+P then Ctrl+Q (NOT Ctrl+C — that kills the process)
```

Use **logs** instead unless you specifically need to send stdin or watch real-time stdout of an already-running interactive process.

---

## Logs

```bash
# Most recent
kubectl logs -n wazuh wazuh-manager-master-0
kubectl logs -n wazuh wazuh-manager-master-0 --tail=50
kubectl logs -n wazuh deploy/wazuh-dashboard --tail=100

# Live tail
kubectl logs -n wazuh -l app=wazuh-agent -f --max-log-requests=10

# Previous container instance (after a crash)
kubectl logs -n wazuh wazuh-manager-master-0 --previous

# Specific container
kubectl logs -n kube-system tetragon-abc12 -c tetragon
kubectl logs -n kube-system tetragon-abc12 -c export-stdout

# All pods of a DaemonSet
kubectl logs -n wazuh ds/wazuh-agent --tail=20

# Time-window
kubectl logs -n wazuh wazuh-indexer-0 --since=10m
kubectl logs -n wazuh wazuh-indexer-0 --since-time=2026-05-25T03:00:00Z
```

---

## Port-forward — access cluster services from the VM

```bash
# Wazuh dashboard → laptop pairs with `gcloud compute start-iap-tunnel`
kubectl port-forward svc/dashboard -n wazuh 8443:443

# DVWA
kubectl port-forward svc/vulnerable-webapp-svc -n vulnerable-apps 30000:80

# Wazuh manager API (queries from VM curl)
kubectl port-forward svc/wazuh -n wazuh 55000:55000

# Indexer (direct OpenSearch)
kubectl port-forward svc/indexer -n wazuh 9200:9200

# Background it
nohup kubectl port-forward svc/dashboard -n wazuh 8443:443 >/dev/null 2>&1 &
```

---

## File transfer (kubectl cp)

```bash
# Pod → local
kubectl cp wazuh/wazuh-manager-master-0:/var/ossec/etc/ossec.conf ./ossec.conf

# Local → pod
kubectl cp ./0700-tetragon_rules.xml wazuh/wazuh-manager-master-0:/var/ossec/etc/rules/0700-tetragon_rules.xml

# Specific container
kubectl cp wazuh/wazuh-agent-abc12:/var/ossec/logs/ossec.log ./agent.log -c wazuh-agent
```

---

## Lab-specific commands

### Tetragon — stream events

```bash
POD=$(kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon -o name | head -1)
kubectl exec -n kube-system $POD -c tetragon -- \
  tetra getevents -o compact --namespace vulnerable-apps

# Scope to a specific pod's node
TARGET_NODE=$(kubectl get pod -n vulnerable-apps -l app=vulnerable-webapp -o jsonpath='{.items[0].spec.nodeName}')
POD=$(kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon \
  -o name --field-selector spec.nodeName=$TARGET_NODE | head -1)
kubectl exec -n kube-system $POD -c tetragon -- tetra getevents -o compact

# Raw log file on a node (via Tetragon pod)
kubectl exec -n kube-system $POD -c tetragon -- \
  tail -f /var/run/cilium/tetragon/tetragon.log
```

### Wazuh — alerts + agents

```bash
# Live alert stream (alerts processed on WORKER, not master!)
kubectl exec -it -n wazuh wazuh-manager-worker-0 -- \
  tail -f /var/ossec/logs/alerts/alerts.json | \
  python3 -c "import sys,json;[print(json.dumps(json.loads(l).get('rule',{}),indent=2)) for l in sys.stdin]"

# Count tetragon alerts
kubectl exec -n wazuh wazuh-manager-worker-0 -- \
  grep -c tetragon /var/ossec/logs/alerts/alerts.json

# Last 5 tetragon alerts, rule ID + description
kubectl exec -n wazuh wazuh-manager-worker-0 -- bash -c \
  "grep tetragon /var/ossec/logs/alerts/alerts.json | tail -5 | python3 -c \"
import sys,json
for l in sys.stdin:
    a=json.loads(l); print(a['rule']['id'],'|',a['rule']['description'])\""

# Registered agents
kubectl exec -n wazuh wazuh-manager-master-0 -- /var/ossec/bin/manage_agents -l

# Cluster sync status
kubectl exec -n wazuh wazuh-manager-master-0 -- /var/ossec/bin/cluster_control -l

# Agent groups
kubectl exec -n wazuh wazuh-manager-master-0 -- /var/ossec/bin/agent_groups -l

# Test a raw log line through the decoder/rules
kubectl exec -i -n wazuh wazuh-manager-master-0 -- /var/ossec/bin/wazuh-logtest < /tmp/sample-tetragon.json

# Agent connection state (events sent, last keepalive)
AGENT=$(kubectl -n wazuh get pods -l app=wazuh-agent -o name | head -1)
kubectl exec -n wazuh $AGENT -- cat /var/ossec/var/run/wazuh-agentd.state

# Force agent restart (in-place, no pod restart)
kubectl exec -n wazuh $AGENT -- /var/ossec/bin/wazuh-control restart
```

### Trigger detection events

```bash
# Sensitive file read → rule 700007
kubectl exec -n vulnerable-apps deploy/vulnerable-webapp -- cat /etc/shadow

# Spawn shell → rule 700004 + 700010
kubectl exec -it -n vulnerable-apps deploy/vulnerable-webapp -- bash

# curl/wget (DVWA image has no curl by default — install or use sh)
kubectl exec -n vulnerable-apps deploy/vulnerable-webapp -- sh -c 'apt-get update && apt-get install -y curl && curl https://example.com'
# Easier: run from netshoot if you bring it back
# kubectl run net --image=nicolaka/netshoot -n vulnerable-apps --rm -it -- curl https://example.com

# Process enumeration
kubectl exec -n vulnerable-apps deploy/vulnerable-webapp -- ps aux

# Privilege escalation tool → rule 700008
kubectl exec -n vulnerable-apps deploy/vulnerable-webapp -- sudo id 2>&1 || true
```

---

## Cluster ops

```bash
# Current context (should be kind-security-lab)
kubectl config current-context
kubectl config get-contexts

# Switch namespace as default
kubectl config set-context --current --namespace=wazuh

# Re-export kubeconfig from kind
kind get kubeconfig --name security-lab > ~/.kube/config

# Cordon a node (no new pods)
kubectl cordon security-lab-worker
kubectl uncordon security-lab-worker

# Restart workloads
kubectl rollout restart ds/wazuh-agent -n wazuh
kubectl rollout restart statefulset/wazuh-manager-worker -n wazuh
kubectl rollout status ds/wazuh-agent -n wazuh
```

---

## Kustomize

```bash
# Dry-render (does NOT apply) — useful to debug overlay merging
kubectl kustomize manifests/namespaces
kubectl kustomize $WAZUH_DIR/envs/local-env/ | grep -A5 "kind: StorageClass"

# Apply / diff / delete a kustomization
kubectl apply -k manifests/namespaces
kubectl diff -k manifests/namespaces
kubectl delete -k manifests/namespaces
```

---

## Helm (Tetragon)

```bash
helm list -A
helm get values tetragon -n kube-system
helm upgrade tetragon cilium/tetragon -n kube-system -f manifests/tetragon/values.yaml
helm rollback tetragon 1 -n kube-system
helm uninstall tetragon -n kube-system
```

---

## Troubleshooting recipes

### Pod won't schedule
```bash
kubectl describe pod <name> -n <ns> | grep -A20 Events
kubectl get events -n <ns> --sort-by=.lastTimestamp | tail
# Usually: PVC binding, resource requests, taints, image pull
```

### PVC stuck Pending
```bash
kubectl get pvc -n wazuh
kubectl get sc                                # is the SC correct?
kubectl describe pvc <name> -n wazuh
kubectl get pv                                # was any PV provisioned?
```

### Image pull errors
```bash
kubectl describe pod <name> -n <ns> | grep -i image
# For custom agent image:
docker exec security-lab-worker crictl images | grep wazuh-agent-local
# Re-load if missing:
kind load docker-image wazuh-agent-local:4.14.1 --name security-lab
```

### Agent enrolled but no alerts
```bash
# Check agent IS sending
kubectl exec -n wazuh $(kubectl -n wazuh get pods -l app=wazuh-agent -o name | head -1) -- \
  cat /var/ossec/var/run/wazuh-agentd.state | grep msg_sent

# Check WORKER's alerts.json (not master's — clustered)
kubectl exec -n wazuh wazuh-manager-worker-0 -- wc -l /var/ossec/logs/alerts/alerts.json

# Confirm rules file exists on BOTH managers
for m in wazuh-manager-master-0 wazuh-manager-worker-0; do
  kubectl exec -n wazuh $m -- ls -la /var/ossec/etc/rules/0700-tetragon_rules.xml
done
```

### Tetragon log empty on a node
```bash
# Verify file is being written on the node
docker exec security-lab-worker ls -la /var/run/cilium/tetragon/

# Check Tetragon config has export enabled
kubectl get cm tetragon-config -n kube-system -o yaml | grep -E "export-(filename|allowlist)"

# Restart the DS if config changed
kubectl rollout restart ds/tetragon -n kube-system
```

### Indexer pod in CrashLoopBackOff
```bash
# Most common cause: vm.max_map_count too low on the kind node
for node in $(kubectl get nodes -o name | sed 's|node/||'); do
  docker exec "$node" sysctl -w vm.max_map_count=262144
done
kubectl rollout restart statefulset/wazuh-indexer -n wazuh
```

### Dashboard shows ERROR3099
```bash
kubectl exec -it wazuh-manager-master-0 -n wazuh -- \
  grep -iE "CRITICAL|modulesd.*ERROR" /var/ossec/logs/ossec.log | tail
# Usually inotify limit. Set on host:
sudo sysctl -w fs.inotify.max_user_watches=524288
sudo sysctl -w fs.inotify.max_user_instances=512
kubectl exec wazuh-manager-master-0 -n wazuh -- /var/ossec/bin/wazuh-control restart
```

---

## One-line aliases (add to `~/.bashrc` on the VM)

```bash
alias k='kubectl'
alias kgp='kubectl get pods -A'
alias kgs='kubectl get svc -A'
alias kw='kubectl get pods -A -w'
alias kex='kubectl exec -it'
alias klog='kubectl logs -f --tail=50'
alias kall='kubectl get all -A'

# Lab-specific
alias wz-master='kubectl exec -it -n wazuh wazuh-manager-master-0 --'
alias wz-worker='kubectl exec -it -n wazuh wazuh-manager-worker-0 --'
alias wz-alerts='kubectl exec -n wazuh wazuh-manager-worker-0 -- tail -f /var/ossec/logs/alerts/alerts.json'
alias dvwa-sh='kubectl exec -it -n vulnerable-apps deploy/vulnerable-webapp -- bash'
alias tetra-ev='POD=$(kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon -o name | head -1); kubectl exec -n kube-system $POD -c tetragon -- tetra getevents -o compact --namespace vulnerable-apps'
```
