# Only the tunnel object. Its ingress is NOT described here and must not be:
# cloudflare_zero_trust_tunnel_cloudflared_config replaces the whole rule list,
# and this tunnel also carries routes for services unrelated to Voltius.
resource "cloudflare_zero_trust_tunnel_cloudflared" "oracle" {
  account_id = var.account_id
  name       = "oracle"
  config_src = "cloudflare"
}

import {
  to = cloudflare_zero_trust_tunnel_cloudflared.oracle
  id = "${var.account_id}/c500bb72-ffa3-4c2f-a68b-83e67009b0bf"
}
