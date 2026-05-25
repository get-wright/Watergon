#!/usr/bin/env bash
# Pre-bake tools + kernel tuning into the lab image.
# Run inside Packer build VM as root.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

KIND_VERSION="${KIND_VERSION:-v0.31.0}"

echo "==> apt update + base packages"
apt-get update -y
apt-get install -y \
  curl wget gpg jq git python3-pip \
  apt-transport-https ca-certificates lsb-release \
  conntrack socat

echo "==> Docker"
curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
sh /tmp/get-docker.sh
rm /tmp/get-docker.sh
systemctl enable docker

echo "==> kubectl"
KVER=$(curl -Ls https://dl.k8s.io/release/stable.txt)
curl -L -o /tmp/kubectl "https://dl.k8s.io/release/${KVER}/bin/linux/amd64/kubectl"
install -o root -g root -m 0755 /tmp/kubectl /usr/local/bin/kubectl
rm /tmp/kubectl

echo "==> kind ${KIND_VERSION}"
curl -Lo /tmp/kind "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-amd64"
install -o root -g root -m 0755 /tmp/kind /usr/local/bin/kind
rm /tmp/kind

echo "==> helm"
curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

echo "==> k9s (deb)"
wget -q "https://github.com/derailed/k9s/releases/latest/download/k9s_linux_amd64.deb" -O /tmp/k9s.deb
apt-get install -y /tmp/k9s.deb
rm /tmp/k9s.deb

echo "==> sysctl tuning (inotify + map_count for Wazuh indexer)"
cat >/etc/sysctl.d/99-watergon.conf <<EOF
fs.inotify.max_user_watches=524288
fs.inotify.max_user_instances=512
vm.max_map_count=262144
EOF
sysctl --system

echo "==> clean apt cache to shrink image"
apt-get clean
rm -rf /var/lib/apt/lists/*

echo "==> Versions baked:"
docker --version
kubectl version --client
kind --version
helm version --short
k9s version --short 2>&1 | head -1 || true

echo "==> Image baking done"
