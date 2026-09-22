variable "account_id" {
  type        = string
  description = "Cloudflare account that owns the zone, the tunnel and the R2 buckets."
}

variable "zone_id" {
  type        = string
  description = "voltius.app zone."
}
