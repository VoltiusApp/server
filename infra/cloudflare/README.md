# Cloudflare configuration

OpenTofu (`tofu`, the MPL-2.0 fork of Terraform — the Cloudflare provider is the same one) describing
the Cloudflare side of production: the `voltius.app` zone's DNS and the R2 buckets.

Everything here was adopted from resources that already existed. The config was generated from the
live API and the first plan reported `21 to import, 0 to add, 0 to change, 0 to destroy`, so adopting
it changed nothing.

## Running it

The API token is never stored here. Supply it in the environment:

```sh
export CLOUDFLARE_API_TOKEN=...   # account-owned token, see Permissions below
export TF_VAR_account_id=...      # Cloudflare account that owns the zone
export TF_VAR_zone_id=...         # voltius.app
tofu init
tofu plan
```

The account and zone IDs are inputs with no defaults, and `*.tfvars` is gitignored. They are
identifiers rather than credentials and grant nothing on their own, but this repository is public and
there is no reason to publish which account to aim at.

State is local and gitignored. That is deliberate: one operator, one machine. A remote backend costs
an R2 bucket, a lock table and a bootstrap problem, and buys nothing until a second person or a CI
job runs `apply`. The state file holds no secret — the token comes from the environment and no
resource here has a sensitive attribute — so losing it costs a re-import, not an outage.

## Permissions

The token needs, on the account that owns the zone:

| Scope | Permission | For |
|---|---|---|
| Zone → `voltius.app` | DNS: Edit | `cloudflare_dns_record` |
| Zone → `voltius.app` | Zone: Read | reading zone metadata |
| Account | Workers R2 Storage: Edit | `cloudflare_r2_bucket` |
| Account | Account Settings: Read | resolving the account |
| Account | Cloudflare One Connector: cloudflared, Edit | tunnel (not yet described here) |

The tunnel permission is listed as `Cloudflare One Connector: cloudflared`, `Cloudflare One
Connectors` or `Cloudflare Tunnel` depending on dashboard rollout; any of the three authorises the
`cfd_tunnel` endpoints.

## What is deliberately not here

**R2 lifecycle rules.** Each bucket carries only Cloudflare's auto-created
`Default Multipart Abort Rule` (abort incomplete multipart uploads after 7 days), and
`cloudflare_r2_bucket_lifecycle` does not support import in provider 5.25.0 — declaring it would make
OpenTofu *create* a rule over the platform default rather than adopt it. Backup retention is also not
a lifecycle concern here: WAL-G prunes to the last 14 base backups and rclone mirrors the dump
rotation, so a server-side expiry rule could delete a base backup out from under a WAL chain.

**The tunnel's ingress rules.** The `oracle` tunnel object is described, and `api.voltius.app`'s
proxied CNAME to `<tunnel-id>.cfargotunnel.com` is a normal DNS record here, but the ingress list is
left to the dashboard on purpose. `cloudflare_zero_trust_tunnel_cloudflared_config` replaces the
whole rule list, and this tunnel also routes hostnames that have nothing to do with Voltius — adopting
it would mean either carrying those rules in this public repository or deleting them on the next
apply. Do not add that resource without every rule the tunnel serves.

**Compute.** The Oracle instance stays clickops until there is a second machine; `tofu import` can
adopt it later without a rebuild.
