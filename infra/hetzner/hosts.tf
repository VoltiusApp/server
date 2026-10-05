resource "hcloud_ssh_key" "controller" {
  name       = "voltius-controller"
  public_key = var.host_ssh_authorized_keys[0]
}

# SSH only, and only from the controller: the API arrives through the tunnel,
# whose connector dials out. No outbound rule means all outbound is allowed.
resource "hcloud_firewall" "host" {
  name = "voltius-host"

  rule {
    description = "ssh from the controller"
    direction   = "in"
    protocol    = "tcp"
    port        = "22"
    source_ips  = var.ssh_source_ips
  }
}

resource "hcloud_server" "host" {
  for_each = var.hosts

  name         = each.key
  server_type  = each.value.server_type
  location     = each.value.location
  image        = "ubuntu-24.04"
  ssh_keys     = [hcloud_ssh_key.controller.id]
  firewall_ids = [hcloud_firewall.host.id]

  delete_protection  = each.value.protected
  rebuild_protection = each.value.protected

  # GHCR has no IPv6 endpoint, so the host needs an IPv4 address to pull the image.
  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }

  # Hetzner images log in as root; the playbooks expect ubuntu with passwordless sudo.
  user_data = "#cloud-config\n${yamlencode({
    users = [{
      name                = "ubuntu"
      groups              = ["sudo"]
      shell               = "/bin/bash"
      sudo                = "ALL=(ALL) NOPASSWD:ALL"
      ssh_authorized_keys = var.host_ssh_authorized_keys
    }]
    disable_root = true
    ssh_pwauth   = false
  })}"

  labels = {
    role = "voltius"
  }

  # Each of these forces a replacement, which on the production host means a new, empty machine.
  lifecycle {
    ignore_changes = [user_data, ssh_keys, image]
  }
}

output "host_ips" {
  value       = { for k, v in hcloud_server.host : k => v.ipv4_address }
  description = "Feed these into ansible/inventory.yml as ansible_host."
}
