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
