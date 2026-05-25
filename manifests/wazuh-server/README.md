# wazuh-server overrides

This directory contains files that get **copied INTO the cloned `wazuh-kubernetes` repo** at deploy time by `scripts/bootstrap.sh`. They are not applied directly via `kubectl apply -k`.

Why this approach: the upstream `wazuh-kubernetes` Kustomize base has the StorageClass `provisioner` field commented out, so a normal strategic merge patch cannot inject it. The only reliable fix is to edit the base file.

## File mapping

| Local | Copies into upstream |
|-------|----------------------|
| `overrides/base-storage-class.yaml` | `wazuh/base/storage-class.yaml` |
| `overrides/local-env-storage-class.yaml` | `envs/local-env/storage-class.yaml` |
| `overrides/services-clusterip-patch.yaml` | `envs/local-env/services-clusterip-patch.yaml` |
| `overrides/kustomization.yml` | `envs/local-env/kustomization.yml` |

bootstrap.sh also runs `sed` against `wazuh/wazuh_managers/wazuh-master-sts.yaml` and `wazuh-worker-sts.yaml` to bump the manager resource limits from 400m/512Mi to 2/2Gi.

## extras/

Post-deploy resources (currently empty placeholder). Add Active Response ConfigMap patches here.
