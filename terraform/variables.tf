variable "project_id" {
  type        = string
  description = "GCP project ID."
}

variable "region" {
  type    = string
  default = "asia-southeast1"
}

variable "zone" {
  type    = string
  default = "asia-southeast1-c"
}

variable "instance_name" {
  type    = string
  default = "tetragon-wazuh-lab"
}

variable "machine_type" {
  type        = string
  default     = "e2-standard-8"
  description = "8 vCPU / 32 GB. Lower at your own risk — Wazuh indexer + manager pair are the tight spot."
}

variable "disk_size_gb" {
  type    = number
  default = 200
}

variable "image_family" {
  type    = string
  default = "watergon-lab"
}

variable "network" {
  type        = string
  default     = "default"
  description = "VPC name. Must have Cloud NAT for egress and an IAP SSH firewall rule (35.235.240.0/20 → tcp:22)."
}

variable "subnetwork" {
  type        = string
  default     = "default"
  description = "Subnet within the VPC. Must reside in the same region as the VM zone."
}

variable "use_spot" {
  type        = bool
  default     = true
  description = "SPOT instance ~70% cheaper. Can be preempted; lab state is ephemeral so fine."
}
