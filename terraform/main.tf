terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

# Latest image from the family baked by Packer.
data "google_compute_image" "lab" {
  family  = var.image_family
  project = var.project_id
}

resource "google_compute_instance" "lab" {
  name         = var.instance_name
  zone         = var.zone
  machine_type = var.machine_type

  scheduling {
    provisioning_model          = var.use_spot ? "SPOT" : "STANDARD"
    preemptible                 = var.use_spot
    automatic_restart           = var.use_spot ? false : true
    instance_termination_action = var.use_spot ? "STOP" : null
  }

  boot_disk {
    auto_delete = true
    device_name = var.instance_name
    initialize_params {
      image = data.google_compute_image.lab.self_link
      size  = var.disk_size_gb
      type  = "pd-balanced"
    }
  }

  network_interface {
    network    = var.network
    subnetwork = var.subnetwork
    # No access_config block = no public IP. Egress via Cloud NAT.
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    enable-oslogin = "FALSE"
  }

  metadata_startup_script = file("${path.module}/../scripts/bootstrap.sh")

  labels = {
    purpose    = "tetragon-wazuh-lab"
    managed-by = "terraform"
  }

  allow_stopping_for_update = true
}
