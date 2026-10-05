# Hetzner configuration

OpenTofu for hosts on Hetzner Cloud, the equivalent of `infra/oci` for a provider where
a bigger machine costs money rather than nothing. It creates machines and nothing else.
`ansible/site.yml` turns one into a voltius host, and `ansible/migrate.yml` moves
production onto it. Neither knows which provider made it.

## What it creates

- One `hcloud_server` per entry in `var.hosts`, running Ubuntu 24.04.
- A firewall that admits SSH from `var.ssh_source_ips` and nothing else. The API arrives
  through the `voltius-api` tunnel, whose connector dials out.
- An `ubuntu` user with passwordless sudo and the controller's key, set up by cloud-init.
  Root login is disabled; the playbooks expect `ubuntu`.

`user_data`, `ssh_keys` and `image` are ignored after creation. Each of them forces a
replacement, which on the production host would mean a new, empty machine. Rotate keys
over SSH instead.

## Pick an arm64 type

Use a **CAX** server type (Ampere, aarch64), the same architecture as the Oracle host.
The database moves as a physical WAL-G base backup, and Postgres does not support
restoring a physical backup on a different architecture. An x86 type (CX, CPX, CCX)
may work, but only `ansible/rehearse.yml` on that machine can tell you. CAX types are
offered in `fsn1`, `nbg1` and `hel1`.

## Credentials

Hetzner Console → the project → **Security** → **API tokens** → **Generate API token**,
with **Read & Write**. It controls every resource in that project, so give voltius a
project of its own.

Add these to `$ROOT/voltius-tofu/.env.tofu`, beside the Cloudflare and OCI entries:

```sh
HCLOUD_TOKEN=…
TF_VAR_ssh_source_ips=["<controller public IPv4>/32"]
```

`TF_VAR_host_ssh_authorized_keys` is already there for `infra/oci` and is read here too.
Re-pack the secrets bundle afterwards (`docs/runbooks/bootstrap-host.md`).

## Using it

```sh
cd $ROOT/voltius-tofu/infra/hetzner
set -a && . "$ROOT/voltius-tofu/.env.tofu" && set +a
tofu init
TF_VAR_hosts='{"rehearsal":{"server_type":"cax21"}}' tofu apply
tofu output host_ips
```

Add each address to `ansible/inventory.yml` as `ansible_host`, then follow
`ansible/README.md`. Its rehearsal is the step to run first on a new provider.

`var.hosts` is not persisted anywhere. Pass the same value on every run, or the next
apply destroys whatever you left out. For a host that is going to stay, put the value in
`.env.tofu` as `TF_VAR_hosts` and set `"protected": true` on the production host. That
turns on Hetzner's delete and rebuild protection, so even a wrong `var.hosts` cannot
remove it.

State is local, as in the other configurations, at
`$ROOT/voltius-tofu/infra/hetzner/terraform.tfstate`. The state backup unit watches it
once `ansible/site.yml` has re-rendered the units on the controller.
