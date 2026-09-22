# Rebuilding the production host

`ansible/` supersedes `scripts/bootstrap-host.sh` for both jobs below: `site.yml` prepares a host
and `migrate.yml` moves production onto it. This page stays as the description of what has to
arrive from where, and as the manual path if Ansible is not available.

What to do when the box is gone, or when a second one has to be stood up. It assumes a fresh Ubuntu
24.04 aarch64 machine with passwordless sudo and nothing else.

Three things have to arrive from somewhere, and only one of them is in git:

| Thing | Where it comes from |
|---|---|
| Stack definitions | this repo (`compose.db.yml`, `pg-walg/`, `compose.prod.yml`) |
| Database contents | the R2 WAL-G archive — `restore-database.md` |
| Secrets | the age-encrypted bundle in R2 — `scripts/secrets-bundle.sh` |

The server image itself comes from GHCR, so nothing is compiled on the host.

## The secrets bundle

`.env.dockhand`, `.env.db`, `cloudflared/.env`, `cloudflared-api/.env`, `voltius-tofu/.env.tofu` and
`voltius-tofu/oci_api_key.pem` exist nowhere else. No database backup contains
them, and losing `JWT_SECRET` alone signs every user out permanently. `scripts/secrets-bundle.sh`
tars them, encrypts them to an age recipient, and uploads them to
`s3://<bucket>/voltius-prod/secrets/`, keeping `secrets-latest.tar.age` as the pointer.

```sh
cd /home/ubuntu/fourretout/voltius-db && set -a && . ./.env.db && set +a
AGE_RECIPIENTS=age1... \
  DOCKHAND_ENV_FILE=/var/lib/docker/volumes/dockhand_dockhand_data/_data/stacks/Docker/voltius/.env.dockhand \
  /path/to/scripts/secrets-bundle.sh pack
```

`DOCKHAND_ENV_FILE` is needed on **this** host and only for `.env.dockhand`: the live copy sits in
the dockhand volume rather than under `$ROOT`, and is root-owned, so `pack` reads it through
passwordless sudo. Without it the run still succeeds and uploads a bundle with every production
secret missing. A rebuilt host keeps its env files under `$ROOT` and needs none of this.

**Run it after every change to any of those files**, and keep the age private key off this
machine — a key stored beside the bundle protects nothing. `verify` lists what the bucket holds.

Restoring, on the new host:

```sh
AGE_IDENTITY=~/age-voltius.key R2_BUCKET=... R2_ENDPOINT=... R2_ACCESS_KEY_ID=... \
  R2_SECRET_ACCESS_KEY=... scripts/secrets-bundle.sh unpack
```

`unpack` refuses to overwrite an existing env file, so it is safe to re-run.

## Bootstrap

```sh
git clone --depth=1 https://github.com/VoltiusApp/server /tmp/voltius-server
/tmp/voltius-server/scripts/bootstrap-host.sh --check   # preflight only
/tmp/voltius-server/scripts/bootstrap-host.sh
```

In order, it installs Docker and age, creates the `cloudflare` network **on the fixed subnet
172.22.0.0/16** (`TRUSTED_PROXIES` in `.env.dockhand` names that subnet — a different one silently
puts every client in one rate-limit bucket), lays out `voltius-db/`, `voltius-server/`,
`voltius-tofu/` and `cloudflared/` under `/home/ubuntu/fourretout`, installs the systemd path unit
that copies the OpenTofu state to R2 whenever it changes, checks the three env files are present, then
starts the database stack, the server and the tunnel and waits for health.

It stops rather than guess if the database volume `voltius-db_db-data` does not exist: restore it
first with `restore-database.md`, then re-run.

The generated `cloudflared/compose.yml` reads the tunnel token from `TUNNEL_TOKEN` in
`cloudflared/.env`. Do not put it back on the command line — anything that can run `docker inspect`
can read a command line.

The layout it produces is not quite the one the current box grew into: today the server's compose
tree and `.env.dockhand` live inside the dockhand Docker volume (`deploy-server.md`), not in
`/home/ubuntu/fourretout/voltius-server`. A rebuilt host gets the plain directory, and
`secrets-bundle.sh` reads `.env.dockhand` from there — pack it from wherever it actually is.

## What this does not cover

- **Provisioning the machine.** Creating the instance, its disk and its firewall rules is still
  manual, and stays that way until there is a second machine.
- **Nothing about OpenTofu, beyond laying it out.** The `voltius-tofu/` checkout, its `.env.tofu`
  from the bundle and the state watch all come back, so a rebuilt host can `apply` — but it will not
  do so on its own. The state is recoverable from `voltius-prod/tofu/` in the backup bucket, and is
  rebuildable from the import blocks even without that.
- **The tunnel's ingress rules.** A rebuilt host reuses the existing tunnel token, so the hostname
  follows the tunnel; the routes live in Cloudflare and are deliberately not described in OpenTofu —
  that tunnel also serves hostnames unrelated to voltius.
- **Anything that is not voltius** — vaultwarden, dockhand, the dev containers. The script starts
  what production needs and nothing else.

## Verify

```sh
curl -fsS http://127.0.0.1:14372/health
curl -fsS https://api.voltius.app/health/deep
docker logs --tail 5 voltius-backup-watch
```

The last one should reach `all checks passed, heartbeat sent` within `BACKUP_WATCH_INTERVAL`
(15 min). Until it does, Instatus will not go green — see `monitoring.md`.
