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
an R2 bucket, a lock story and a bootstrap problem — the bucket would have to exist before the thing
that manages buckets could run — and buys nothing until a second person or a CI job runs `apply`. The
local backend does take a lockfile, so two runs on this host serialise; only cross-machine
concurrency is unprotected, and there is one machine.

The state file holds no secret: the token comes from the environment and no resource here has a
sensitive attribute. Keep it mode 600 anyway — this host runs other containers.

## Do not delete imports.tf

The import blocks are what make losing the state cheap. They are inert once the resources are
adopted — a plan with them present reports no changes — and they hardcode every resource ID, so a
destroyed state is rebuilt by one import-only apply rather than by reconstructing DNS. Deleting them
as spent scaffolding is the obvious tidy-up and it is the one thing that would turn a lost file into
real work.

### Rebuilding state from scratch

```sh
cd infra/cloudflare
tofu init
tofu plan      # expect "N to import, 0 to add, 0 to change, 0 to destroy"
tofu apply     # refuse to proceed if anything other than imports appears
```

If the plan wants to add, change or destroy anything, something drifted in the dashboard. Reconcile
the config with reality first; do not let an apply "fix" it.

## Backing the state up

`scripts/backup-tofu-state.sh` copies it to `voltius-prod/tofu/` in the R2 backup bucket, as
`terraform.tfstate` plus a timestamped copy, which also gives the history a local backend does not:

```sh
./scripts/backup-tofu-state.sh infra/cloudflare/terraform.tfstate /path/to/.env.db
```

Credentials come from the database stack's env file, injected by docker; the script never reads them.
Run it after any apply.

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
