output "instance_name" {
  value = google_compute_instance.lab.name
}

output "instance_zone" {
  value = google_compute_instance.lab.zone
}

output "internal_ip" {
  value = google_compute_instance.lab.network_interface[0].network_ip
}

output "ssh_command" {
  value = "gcloud compute ssh ${google_compute_instance.lab.name} --zone=${google_compute_instance.lab.zone} --project=${var.project_id}"
}

output "dashboard_tunnel_command" {
  value = "gcloud compute start-iap-tunnel ${google_compute_instance.lab.name} 8443 --zone=${google_compute_instance.lab.zone} --project=${var.project_id} --local-host-port=localhost:8443"
}
