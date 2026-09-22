# A tunnel of its own for api.voltius.app, so a host move is a DNS change rather
# than a second connector on the shared tunnel — two connectors on one tunnel
# split every hostname it carries, including the ones that are not voltius.
# Its ingress may live here for the same reason: nothing else uses it.
resource "cloudflare_zero_trust_tunnel_cloudflared" "voltius_api" {
  account_id = var.account_id
  name       = "voltius-api"
  config_src = "cloudflare"
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "voltius_api" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.voltius_api.id

  config = {
    ingress = [
      {
        hostname = "api.voltius.app"
        service  = "http://voltius-server:8080"
      },
      {
        service = "http_status:404"
      },
    ]
  }
}

locals {
  api_tunnel_id = var.api_tunnel == "voltius-api" ? cloudflare_zero_trust_tunnel_cloudflared.voltius_api.id : cloudflare_zero_trust_tunnel_cloudflared.oracle.id
}
