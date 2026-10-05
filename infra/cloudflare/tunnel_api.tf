# A tunnel of its own for api.voltius.app, so a host move is moving its one
# connector. Two connectors on a tunnel split traffic between them; on the shared
# tunnel that would include hostnames that are not voltius.
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

