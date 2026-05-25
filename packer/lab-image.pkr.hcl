packer {
  required_plugins {
    googlecompute = {
      source  = "github.com/hashicorp/googlecompute"
      version = ">= 1.1.0"
    }
  }
}

variable "project_id" {
  type        = string
  description = "GCP project for building the image."
}

variable "zone" {
  type    = string
  default = "asia-southeast1-c"
}

variable "image_family" {
  type    = string
  default = "watergon-lab"
}

variable "source_image_family" {
  type    = string
  default = "ubuntu-2204-lts"
}

variable "machine_type" {
  type    = string
  default = "e2-medium"
}

variable "network" {
  type        = string
  default     = "default"
  description = "VPC to use for the Packer build VM."
}

variable "subnetwork" {
  type        = string
  default     = "default"
  description = "Subnet to use for the Packer build VM."
}

locals {
  image_name = "${var.image_family}-${formatdate("YYYYMMDD-hhmm", timestamp())}"
}

source "googlecompute" "lab" {
  project_id              = var.project_id
  zone                    = var.zone
  source_image_family     = var.source_image_family
  source_image_project_id = ["ubuntu-os-cloud"]
  image_name              = local.image_name
  image_family            = var.image_family
  image_description       = "Watergon lab base: Docker + kubectl + kind + helm + sysctl tuned."
  ssh_username            = "packer"
  machine_type            = var.machine_type
  disk_size               = 20
  disk_type               = "pd-balanced"

  # IAP tunneling for SSH (no public IP needed if VPC has Cloud NAT)
  use_iap                 = true
  use_internal_ip         = true
  omit_external_ip        = true
  subnetwork              = var.subnetwork
  network                 = var.network

  metadata = {
    enable-oslogin = "FALSE"
  }
}

build {
  name    = "watergon-lab"
  sources = ["source.googlecompute.lab"]

  provisioner "shell" {
    execute_command = "echo 'packer' | sudo -S bash -c '{{ .Vars }} {{ .Path }}'"
    script          = "${path.root}/scripts/install-tools.sh"
  }

  post-processor "manifest" {
    output     = "manifest.json"
    strip_path = true
  }
}
