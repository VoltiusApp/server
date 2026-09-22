#!/usr/bin/env bash
# Bring a fresh Ubuntu aarch64 host to serving voltius. See docs/runbooks/bootstrap-host.md.
set -euo pipefail

ROOT="${ROOT:-/home/ubuntu/fourretout}"
REPO="${REPO:-https://github.com/VoltiusApp/server}"
REF="${REF:-main}"
# TRUSTED_PROXIES in .env.dockhand names this subnet, so it is fixed, not Docker's default pick.
CLOUDFLARE_SUBNET="${CLOUDFLARE_SUBNET:-172.22.0.0/16}"
CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

log() { echo "[bootstrap] $*"; }
die() { echo "[bootstrap] error: $*" >&2; exit 1; }

preflight() {
  [ "$(uname -m)" = "aarch64" ] || log "warning: host is $(uname -m); prod images are built for arm64 too, continuing"
  [ "$(id -u)" -ne 0 ] || die "run as the unprivileged owner of $ROOT, not root"
  sudo -n true 2>/dev/null || die "passwordless sudo is required"
  for c in git curl tar; do command -v "$c" >/dev/null || die "$c is missing"; done
}

install_docker() {
  if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
    log "docker $(docker --version | awk '{print $3}' | tr -d ,) and compose already present"
    return
  fi
  log "installing docker engine + compose plugin"
  curl -fsSL https://get.docker.com | sudo sh
  sudo usermod -aG docker "$USER"
  sudo systemctl enable --now docker
  log "log out and back in for the docker group, then re-run"
  exit 1
}

install_age() {
  command -v age >/dev/null && return
  log "installing age"
  sudo apt-get update -qq && sudo apt-get install -y -qq age
}

create_network() {
  if docker network inspect cloudflare >/dev/null 2>&1; then
    local subnet; subnet=$(docker network inspect cloudflare --format '{{(index .IPAM.Config 0).Subnet}}')
    [ "$subnet" = "$CLOUDFLARE_SUBNET" ] || die "network cloudflare exists with subnet $subnet, expected $CLOUDFLARE_SUBNET"
    log "network cloudflare present ($subnet)"
    return
  fi
  log "creating network cloudflare ($CLOUDFLARE_SUBNET)"
  docker network create --subnet "$CLOUDFLARE_SUBNET" cloudflare >/dev/null
}

checkout() {
  local dir="$1"; shift
  if [ -d "$dir/.git" ]; then
    log "updating checkout $dir"
    git -C "$dir" fetch -q --depth=1 origin "$REF"
    git -C "$dir" reset -q --hard FETCH_HEAD
    return
  fi
  log "creating checkout $dir"
  mkdir -p "$dir"
  git -C "$dir" init -q -b main
  git -C "$dir" remote add origin "$REPO"
  git -C "$dir" fetch -q --depth=1 origin "$REF"
  git -C "$dir" sparse-checkout set --no-cone "$@"
  git -C "$dir" reset -q --hard FETCH_HEAD
}

lay_out() {
  checkout "$ROOT/voltius-db" /compose.db.yml /pg-walg/ /.env.db.example /.gitignore
  checkout "$ROOT/voltius-server" /compose.prod.yml /.env.example
  checkout "$ROOT/voltius-tofu" /infra/cloudflare/ /infra/oci/ /ansible/ /scripts/backup-tofu-state.sh /.gitignore
  mkdir -p "$ROOT/cloudflared"
  cat > "$ROOT/cloudflared/compose.yml" <<'YAML'
# Token lives in .env beside this file, never in the command line: anything that can
# run `docker inspect` can read a command line.
services:
  tunnel:
    image: cloudflare/cloudflared:latest
    container_name: cloudflared-tunnel
    restart: unless-stopped
    command: tunnel run
    environment:
      TUNNEL_TOKEN: ${TUNNEL_TOKEN:?set TUNNEL_TOKEN in cloudflared/.env}
    networks: [cloudflare]

networks:
  cloudflare:
    external: true
YAML
}

# A path unit, not a timer: the state only changes when someone runs `tofu apply`,
# so polling would either lag or run all day for nothing.
install_state_watch() {
  local cf="$ROOT/voltius-tofu/infra/cloudflare/terraform.tfstate"
  local oci="$ROOT/voltius-tofu/infra/oci/terraform.tfstate"
  log "installing the OpenTofu state watch"
  sudo tee /etc/systemd/system/voltius-tofu-state-backup.service >/dev/null <<UNIT
[Unit]
Description=Copy the OpenTofu state to the R2 backup bucket
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
Environment=TOFU_STATE_ENV_FILE=$ROOT/voltius-db/.env.db
ExecStart=$ROOT/voltius-tofu/scripts/backup-tofu-state.sh $cf
ExecStart=$ROOT/voltius-tofu/scripts/backup-tofu-state.sh $oci
UNIT
  sudo tee /etc/systemd/system/voltius-tofu-state-backup.path >/dev/null <<UNIT
[Unit]
Description=Watch the OpenTofu state for changes

[Path]
PathChanged=$cf
PathChanged=$oci
Unit=voltius-tofu-state-backup.service

[Install]
WantedBy=multi-user.target
UNIT
  sudo systemctl daemon-reload
  sudo systemctl enable --now voltius-tofu-state-backup.path
}

check_secrets() {
  local missing=0
  for f in voltius-server/.env.dockhand voltius-db/.env.db cloudflared/.env; do
    [ -r "$ROOT/$f" ] || { echo "[bootstrap] missing $ROOT/$f" >&2; missing=1; }
  done
  [ "$missing" -eq 0 ] || die "restore the env files first: AGE_IDENTITY=<key> scripts/secrets-bundle.sh unpack"
  grep -q '^SERVER_TAG=' "$ROOT/voltius-server/.env.dockhand" || die "SERVER_TAG is unset in .env.dockhand"
}

start_db() {
  if docker volume inspect voltius-db_db-data >/dev/null 2>&1; then
    log "volume voltius-db_db-data exists, not restoring"
  else
    die "no database volume: restore it first with docs/runbooks/restore-database.md, then re-run"
  fi
  (cd "$ROOT/voltius-db" && docker compose -f compose.db.yml --env-file .env.db up -d)
}

start_server() {
  (cd "$ROOT/voltius-server" && docker compose -p voltius --env-file .env.dockhand -f compose.prod.yml pull -q server \
    && docker compose -p voltius --env-file .env.dockhand -f compose.prod.yml up -d server)
}

start_tunnel() {
  (cd "$ROOT/cloudflared" && docker compose up -d)
}

verify() {
  local fails=0
  for _ in $(seq 1 30); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' voltius-server 2>/dev/null)" = "healthy" ] && break
    sleep 5
  done
  docker inspect -f '{{.Name}} {{.State.Health.Status}}' voltius-server voltius-db || fails=1
  curl -fsS -o /dev/null http://127.0.0.1:14372/health || { echo "[bootstrap] local /health failed" >&2; fails=1; }
  docker logs --tail 20 voltius-backup-watch 2>&1 | grep -q 'heartbeat sent' \
    || echo "[bootstrap] backup-watch has not passed a round yet (it runs every BACKUP_WATCH_INTERVAL)" >&2
  return "$fails"
}

main() {
  preflight
  install_docker
  create_network
  if [ "$CHECK_ONLY" = 1 ]; then
    check_secrets
    log "checks passed"
    return 0
  fi
  install_age
  lay_out
  install_state_watch
  check_secrets
  start_db
  start_server
  start_tunnel
  verify
  log "done — point DNS at the tunnel and confirm https://api.voltius.app/health/deep"
}

# Sourced by the tests, which call the functions one at a time.
if [ "${BASH_SOURCE[0]:-}" = "$0" ]; then
  main "$@"
fi
