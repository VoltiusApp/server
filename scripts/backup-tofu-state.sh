#!/usr/bin/env bash
# Copy the OpenTofu state off this box into the R2 backup bucket, as the current
# file plus a timestamped copy. Credentials are injected by docker from the
# database stack's env file; this script never reads them.
set -euo pipefail

STATE="${1:-infra/cloudflare/terraform.tfstate}"
ENV_FILE="${TOFU_STATE_ENV_FILE:-${2:-}}"

if [ -z "$ENV_FILE" ]; then
  echo "usage: $0 [state-file] <env-file-with-R2-credentials>" >&2
  echo "   or: TOFU_STATE_ENV_FILE=/path/to/.env.db $0 [state-file]" >&2
  exit 2
fi
[ -f "$STATE" ] || { echo "no state file at $STATE" >&2; exit 1; }
[ -f "$ENV_FILE" ] || { echo "no env file at $ENV_FILE" >&2; exit 1; }

dir=$(cd "$(dirname "$STATE")" && pwd)
base=$(basename "$STATE")
# One prefix per config, or a second one overwrites the first: every state file
# is named terraform.tfstate.
config=$(basename "$dir")
stamp=$(date -u '+%Y%m%dT%H%M%SZ')

docker run --rm \
  --env-file "$ENV_FILE" \
  -v "$dir:/state:ro" \
  --entrypoint sh \
  rclone/rclone:1.69 -c '
    set -eu
    export RCLONE_CONFIG_R2BACKUP_TYPE=s3
    export RCLONE_CONFIG_R2BACKUP_PROVIDER=Cloudflare
    export RCLONE_CONFIG_R2BACKUP_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID"
    export RCLONE_CONFIG_R2BACKUP_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY"
    export RCLONE_CONFIG_R2BACKUP_ENDPOINT="$R2_ENDPOINT"
    export RCLONE_CONFIG_R2BACKUP_ACL=private
    export RCLONE_CONFIG_R2BACKUP_NO_CHECK_BUCKET=true
    dest="r2backup:$R2_BUCKET/voltius-prod/tofu/'"$config"'"
    rclone copyto "/state/'"$base"'" "$dest/terraform.tfstate"
    rclone copyto "/state/'"$base"'" "$dest/terraform.tfstate.'"$stamp"'"
    rclone lsl "$dest"
  '

echo "[backup-tofu-state] ok, stamped $stamp"
