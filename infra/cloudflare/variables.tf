variable "account_id" {
  type        = string
  description = "Cloudflare account that owns the zone, the tunnel and the R2 buckets."
}

variable "zone_id" {
  type        = string
  description = "voltius.app zone."
}

variable "api_tunnel" {
  type        = string
  default     = "oracle"
  description = "Which tunnel api.voltius.app resolves to. Switching it is the host cutover."

  validation {
    condition     = contains(["oracle", "voltius-api"], var.api_tunnel)
    error_message = "api_tunnel must be \"oracle\" or \"voltius-api\"."
  }
}
