# Machines added for capacity. Empty by default, so a plan proposes nothing
# until an entry exists:
#
#   TF_VAR_hosts='{"bigger":{"ocpus":4,"memory_in_gbs":24,"boot_volume_size_in_gbs":200}}'
#
# The free A1 shape cannot be resized, so growing means a new instance and
# ansible/migrate.yml moving production onto it.
variable "hosts" {
  type = map(object({
    shape                   = optional(string, "VM.Standard.A1.Flex")
    ocpus                   = number
    memory_in_gbs           = number
    boot_volume_size_in_gbs = optional(number, 200)
    availability_domain     = optional(string)
  }))
  default     = {}
  description = "Additional hosts to create, keyed by the name used in the Ansible inventory."
}

# The current instance keeps the single key it was created with; new hosts also
# accept the controller's key, which is what runs the playbooks over SSH.
variable "host_ssh_authorized_keys" {
  type        = list(string)
  default     = []
  description = "Public keys for hosts in var.hosts. Empty falls back to ssh_authorized_key."
}

data "oci_core_images" "ubuntu_2404" {
  compartment_id           = var.oci_tenancy_ocid
  operating_system         = "Canonical Ubuntu"
  operating_system_version = "24.04"
  shape                    = "VM.Standard.A1.Flex"
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"
}

resource "oci_core_instance" "host" {
  for_each = var.hosts

  compartment_id      = var.oci_tenancy_ocid
  availability_domain = coalesce(each.value.availability_domain, oci_core_instance.oracle.availability_domain)
  display_name        = each.key
  shape               = each.value.shape

  metadata = {
    ssh_authorized_keys = join("\n", coalescelist(var.host_ssh_authorized_keys, [var.ssh_authorized_key]))
  }

  shape_config {
    ocpus         = each.value.ocpus
    memory_in_gbs = each.value.memory_in_gbs
  }

  source_details {
    source_type             = "image"
    source_id               = data.oci_core_images.ubuntu_2404.images[0].id
    boot_volume_size_in_gbs = each.value.boot_volume_size_in_gbs
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.main.id
    assign_public_ip = false
    display_name     = each.key
  }

  lifecycle {
    ignore_changes = [defined_tags, freeform_tags, agent_config, source_details[0].source_id]
  }
}

output "host_private_ips" {
  value       = { for k, v in oci_core_instance.host : k => v.private_ip }
  description = "Feed these into ansible/inventory.yml."
}
