#!/usr/bin/env bash
# Pack or restore the env files that no backup contains. See docs/runbooks/bootstrap-host.md.
set -euo pipefail

BUNDLE_PREFIX="${BUNDLE_PREFIX:-voltius-prod/secrets}"
AGE_RECIPIENTS="${AGE_RECIPIENTS:-}"
AGE_IDENTITY="${AGE_IDENTITY:-}"
ROOT="${ROOT:-/home/ubuntu/fourretout}"

FILES=(
  "voltius-server/.env.dockhand"
  "voltius-db/.env.db"
  "cloudflared/.env"
)

WORK=""
cleanup() { [ -n "$WORK" ] && rm -rf "$WORK"; }
trap cleanup EXIT
mkwork() { WORK=$(mktemp -d); }

die() { echo "error: $*" >&2; exit 1; }

need() { command -v "$1" >/dev/null || die "$1 is not installed"; }

rclone_env() {
  [ -n "${R2_ACCESS_KEY_ID:-}" ] || die "R2_ACCESS_KEY_ID is unset (source voltius-db/.env.db)"
  printf '%s\n' \
    "RCLONE_CONFIG_R2_TYPE=s3" \
    "RCLONE_CONFIG_R2_PROVIDER=Cloudflare" \
    "RCLONE_CONFIG_R2_ACCESS_KEY_ID=$R2_ACCESS_KEY_ID" \
    "RCLONE_CONFIG_R2_SECRET_ACCESS_KEY=$R2_SECRET_ACCESS_KEY" \
    "RCLONE_CONFIG_R2_ENDPOINT=$R2_ENDPOINT" \
    "RCLONE_CONFIG_R2_NO_CHECK_BUCKET=true"
}

rclone_run() {
  local envfile; envfile=$(mktemp); rclone_env > "$envfile"
  local dir="$1"; shift
  docker run --rm --env-file "$envfile" -v "$dir:/data" rclone/rclone:1.69 "$@"
  rm -f "$envfile"
}

pack() {
  need age
  [ -n "$AGE_RECIPIENTS" ] || die "AGE_RECIPIENTS is unset (age1... public key, or -R file)"
  mkwork
  local staged=0
  for f in "${FILES[@]}"; do
    if [ -r "$ROOT/$f" ]; then
      install -D -m 600 "$ROOT/$f" "$WORK/bundle/$f"
      staged=$((staged + 1))
    else
      echo "skip (unreadable): $ROOT/$f" >&2
    fi
  done
  [ "$staged" -gt 0 ] || die "nothing to pack"
  local name; name="secrets-$(date -u +%Y%m%d-%H%M%S).tar.age"
  tar -C "$WORK/bundle" -cf - . | age -r "$AGE_RECIPIENTS" -o "$WORK/$name"
  chmod 600 "$WORK/$name"
  rclone_run "$WORK" copyto "/data/$name" "r2:$R2_BUCKET/$BUNDLE_PREFIX/$name"
  rclone_run "$WORK" copyto "/data/$name" "r2:$R2_BUCKET/$BUNDLE_PREFIX/secrets-latest.tar.age"
  echo "packed $staged file(s) -> $BUNDLE_PREFIX/$name (and secrets-latest.tar.age)"
}

unpack() {
  need age
  [ -r "$AGE_IDENTITY" ] || die "AGE_IDENTITY must point at the age private key file"
  mkwork
  rclone_run "$WORK" copyto "r2:$R2_BUCKET/$BUNDLE_PREFIX/secrets-latest.tar.age" /data/secrets.tar.age
  age -d -i "$AGE_IDENTITY" -o "$WORK/secrets.tar" "$WORK/secrets.tar.age"
  for f in "${FILES[@]}"; do
    [ -e "$ROOT/$f" ] && die "$ROOT/$f already exists; move it aside first"
  done
  mkdir -p "$WORK/out" && tar -C "$WORK/out" -xf "$WORK/secrets.tar"
  for f in "${FILES[@]}"; do
    [ -f "$WORK/out/$f" ] || { echo "not in bundle: $f" >&2; continue; }
    install -D -m 600 "$WORK/out/$f" "$ROOT/$f"
    echo "restored $ROOT/$f"
  done
}

verify() {
  mkwork
  rclone_run "$WORK" lsl "r2:$R2_BUCKET/$BUNDLE_PREFIX/" | sort -k2
}

case "${1:-}" in
  pack) pack ;;
  unpack) unpack ;;
  verify) verify ;;
  *) echo "usage: $0 {pack|unpack|verify}" >&2; exit 2 ;;
esac
