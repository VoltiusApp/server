# Relay for device-to-device connections that cannot go direct. The key is the
# bearer token the server uses to mint short-lived TURN credentials.
resource "cloudflare_calls_turn_app" "relay" {
  account_id = var.account_id
  name       = "voltius-relay"
}

output "turn_key_id" {
  value = cloudflare_calls_turn_app.relay.uid
}

output "turn_key_token" {
  value     = cloudflare_calls_turn_app.relay.key
  sensitive = true
}
