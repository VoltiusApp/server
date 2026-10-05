variable "hosts" {
  type = map(object({
    server_type = string
    location    = optional(string, "fsn1")
    # Set on the host that serves production; a rehearsal host leaves it off so it can be destroyed.
    protected = optional(bool, false)
  }))
  default     = {}
  description = "Hosts to create, keyed by the name used in the Ansible inventory."
}

variable "host_ssh_authorized_keys" {
  type        = list(string)
  description = "Public keys for the ubuntu user, the controller's among them. Shared with infra/oci through .env.tofu."

  validation {
    condition     = length(var.host_ssh_authorized_keys) > 0
    error_message = "At least one key is needed: root login is disabled."
  }
}

variable "ssh_source_ips" {
  type        = list(string)
  description = "CIDRs allowed to reach port 22, the controller's public address among them."

  validation {
    condition     = length(var.ssh_source_ips) > 0 && alltrue([for c in var.ssh_source_ips : can(cidrhost(c, 0))])
    error_message = "Give at least one CIDR, such as 203.0.113.7/32."
  }
}
