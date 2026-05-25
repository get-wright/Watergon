# Watergon

Tetragon + Wazuh security lab on a single GCE VM running `kind`. Standardized deploy path: **Packer image → Terraform VM → bootstrap.sh** → working SIEM ingesting eBPF events.

## Why this exists

Setup.md (the original 4000-line walkthrough) takes ~30 min and is fragile across re-runs. This repo collapses it into:

- **One Packer build** that bakes Docker + kubectl + kind + helm + k9s + sysctl into a reusable GCE image (~10 min, once).
- **One `terraform apply`** that provisions the VM from the baked image (~2 min).
- **One `bootstrap.sh`** the VM auto-runs to bring up the kind cluster, Tetragon, Wazuh server + agents, custom rules, and DVWA (~5 min).

Total cold deploy after image bake: **~7 min**. Re-deploy on an existing image: **~5 min**.

## Day-to-day operation

See [`docs/kubectl-cheatsheet.md`](docs/kubectl-cheatsheet.md) — copy-paste recipes for exec/logs/port-forward/Tetragon events/Wazuh alerts/agent enrollment/troubleshooting, all tuned to this lab's namespaces and pod names.

## Repo layout

```
Watergon/
├── packer/                          # GCE image baking
│   ├── lab-image.pkr.hcl
│   └── scripts/install-tools.sh
├── terraform/                       # VM provisioning
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   └── terraform.tfvars.example
├── cluster/
│   └── kind-config.yaml             # 3-node kind cluster spec
├── manifests/                       # Kustomize trees
│   ├── namespaces/                  # vulnerable-apps, security-testing, monitoring, RBAC
│   ├── tetragon/
│   │   ├── values.yaml              # helm values (export config)
│   │   ├── kustomization.yaml
│   │   └── tracingpolicies.yaml     # bonus kernel-level hooks
│   ├── wazuh-server/
│   │   ├── overrides/               # files copied INTO cloned wazuh-kubernetes
│   │   └── extras/                  # post-deploy extras (placeholder)
│   ├── wazuh-agent/
│   │   ├── agent-image/             # Dockerfile + delete-pod.py for custom image
│   │   ├── configmap.yaml
│   │   ├── serviceaccount.yaml
│   │   ├── daemonset.yaml
│   │   ├── rules-cm.yaml            # Tetragon detection rules as ConfigMap
│   │   └── rules-sync-job.yaml      # one-shot Job: create k8s-nodes group + push rules to both managers
│   └── workloads/
│       └── dvwa.yaml
└── scripts/
    └── bootstrap.sh                 # thin orchestrator; runs on the VM
```

## Prerequisites

- A GCP project with billing enabled.
- A VPC + subnet in the target region with **Cloud NAT** (egress for image pulls when the VM has no public IP) and an **IAP SSH firewall rule** allowing `35.235.240.0/20 → tcp:22`. Defaults to `default` network — override in `terraform.tfvars` if you use a custom VPC.
- Local tools: `packer >= 1.10`, `terraform >= 1.5`, `gcloud` authenticated against the project.

If your VPC differs, override `network` / `subnetwork` in `terraform.tfvars`.

## Deploy

### 1. Bake the image (once per major change)

```bash
cd packer
packer init lab-image.pkr.hcl
packer build -var "project_id=your-gcp-project-id" lab-image.pkr.hcl
```

Result: a GCE image in family `watergon-lab`. Terraform always pulls the latest by family.

### 2. Apply Terraform

```bash
cd ../terraform
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars (project_id at minimum)
terraform init
terraform apply
```

Outputs include `ssh_command` and `dashboard_tunnel_command` — copy them.

### 3. Push the repo to the VM

VM startup-script runs `bootstrap.sh`, but the script needs the repo on disk. First run:

```bash
PROJECT=$(terraform output -raw -ne 'var.project_id' 2>/dev/null || echo "your-gcp-project-id")
INSTANCE=$(terraform output -raw instance_name)
ZONE=$(terraform output -raw instance_zone)

gcloud compute scp --recurse ../  $INSTANCE:/tmp/Watergon \
  --zone=$ZONE --project=$PROJECT
gcloud compute ssh $INSTANCE --zone=$ZONE --project=$PROJECT \
  -- "sudo mv /tmp/Watergon /opt/watergon && sudo bash /opt/watergon/scripts/bootstrap.sh"
```

Subsequent re-deploys: `scp` the changed bits, then `sudo bash /opt/watergon/scripts/bootstrap.sh` (idempotent).

## Accessing the dashboard

`bootstrap.sh` installs a systemd unit (`watergon-dashboard-pf.service`) that runs `kubectl port-forward` bound to `0.0.0.0:8443`, waits for the dashboard Service to have ready endpoints, and is restarted by systemd on any exit. So once the lab is up, the port-forward is always there.

On laptop:
```bash
gcloud compute start-iap-tunnel <instance> 8443 \
  --zone=<zone> --project=<project> \
  --local-host-port=localhost:8443
```

Browser: `https://localhost:8443` → admin / SecretPassword → Threat Hunting → Events → filter `rule.groups:"tetragon"`.

**Service controls on the VM:**
```bash
sudo systemctl status watergon-dashboard-pf
sudo journalctl -u watergon-dashboard-pf -f
sudo systemctl restart watergon-dashboard-pf
```

**Why `--address=0.0.0.0` and not loopback?** IAP tunneling connects to the VM via its primary internal IP (nic0), not 127.0.0.1. A loopback-only listener is invisible to the tunnel.

## What this gets you

- **eBPF process visibility** on every node (Tetragon DaemonSet).
- **SIEM** with custom rules firing on shells, curl, package managers, sensitive-file access, privilege escalation, kernel tcp_connect — plus a forensic audit rule (700099) that records every command run in `vulnerable-apps`.
- **DVWA** (PHP, OWASP Top 10 / 2007 vintage) on NodePort 30000.
- **OWASP NodeGoat** (Node.js, OWASP Top 10 / 2017 vintage) on NodePort 30001 — backed by a `mongo:6` sidecar.
- **Active Response** wiring (delete-pod.py in the agent image; wire on the manager via wazuh-conf if desired — currently a follow-up).

## Common operations

```bash
# Stop the VM when idle (kind state persists on disk)
gcloud compute instances stop <instance> --zone=<zone> --project=<project>

# Start it back up
gcloud compute instances start <instance> --zone=<zone> --project=<project>

# Tear down everything (deletes VM + disk)
terraform -chdir=terraform destroy

# Tail the bootstrap log
gcloud compute ssh <instance> --zone=<zone> --project=<project> \
  -- sudo tail -f /var/log/watergon-bootstrap.log
```

## Deltas from original Setup.md

- StorageClass fix applied to BOTH base and `envs/local-env` (Setup.md missed the overlay).
- `k8s-nodes` agent group is created automatically via the `wazuh-rules-sync` Job (Setup.md marked this "optional" but agent enrollment hard-requires it).
- Custom rules are synced to BOTH manager pods (Setup.md only cp'd to master, relied on lazy cluster sync; worker restart raced the sync).
- Wazuh agent DS gets a control-plane toleration so all nodes run an agent (Setup.md only got 2 of 3 nodes).
- Tetragon detection extended with declarative `TracingPolicy` CRDs in addition to the original Wazuh rules.

## Future work

- Push the agent image to Artifact Registry instead of `kind load` (lets you skip the `docker build` step).
- Inject Active Response config into `wazuh-conf` via Kustomize so `delete-pod.py` triggers automatically.
- Multi-environment overlays (e.g. `prod` vs `lab` Kustomize roots).
- GitOps via Flux/ArgoCD once there's a real cluster to keep in sync.
