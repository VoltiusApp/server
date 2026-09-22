provider "cloudflare" {}

resource "cloudflare_r2_bucket" "assets" {
  account_id = var.account_id
  name       = "voltius-assets"
}

resource "cloudflare_r2_bucket" "db_backups" {
  account_id = var.account_id
  name       = "voltius-db-backups"
}

resource "cloudflare_r2_bucket" "repo" {
  account_id = var.account_id
  name       = "voltius-repo"
}

# Only while a migration drill runs. A drill must not write into the production
# prefixes: one rclone sync or one archived second timeline there is real damage.
variable "drill_bucket" {
  type        = bool
  default     = false
  description = "Create the throwaway bucket a migration drill archives into."
}

resource "cloudflare_r2_bucket" "drill" {
  count      = var.drill_bucket ? 1 : 0
  account_id = var.account_id
  name       = "voltius-drill"
}

output "drill_bucket_name" {
  value = one(cloudflare_r2_bucket.drill[*].name)
}
