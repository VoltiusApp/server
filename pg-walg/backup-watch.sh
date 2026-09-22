#!/bin/bash
set -uo pipefail

INTERVAL="${BACKUP_WATCH_INTERVAL:-900}"
ARCHIVE_MAX_AGE="${ARCHIVE_MAX_AGE_SECONDS:-600}"
BACKUP_MAX_AGE="${BACKUP_MAX_AGE_SECONDS:-172800}"
DISK_FREE_MIN="${DISK_FREE_MIN_PERCENT:-15}"
DUMP_DIR="${DUMP_DIR:-/backups}"
DATA_DIR="${DATA_DIR:-/var/lib/postgresql/data}"
CONNECT_WAIT="${DB_CONNECT_WAIT_SECONDS:-120}"

log() { echo "[backup-watch] $(date -u '+%F %T')Z $*"; }

# Compose's depends_on cannot cover this: on a host reboot dockerd starts every
# restart-policy container at once, so this one can outrun Postgres by seconds.
psql_wait() {
  local deadline out
  deadline=$(( $(date -u +%s) + CONNECT_WAIT ))
  while :; do
    if out=$(PGCONNECT_TIMEOUT=10 PGOPTIONS='-c statement_timeout=10000' \
             psql -qtAX -F'|' -c "$1" 2>/dev/null); then
      printf '%s' "$out"
      return 0
    fi
    [ "$(date -u +%s)" -ge "$deadline" ] && return 1
    sleep 5
  done
}

check_archiver() {
  local row mode archived_age failed_newer status_dir pending
  row=$(psql_wait "SELECT current_setting('archive_mode'),
      COALESCE(EXTRACT(EPOCH FROM (now() - last_archived_time))::bigint, -1),
      CASE WHEN last_failed_time IS NOT NULL
            AND (last_archived_time IS NULL OR last_failed_time > last_archived_time)
           THEN 1 ELSE 0 END
    FROM pg_stat_archiver;") \
    || { log "FAIL archiver: no answer from Postgres within ${CONNECT_WAIT}s"; return 1; }

  mode="${row%%|*}"
  row="${row#*|}"
  archived_age="${row%%|*}"
  failed_newer="${row##*|}"

  if [ "$mode" != "on" ] && [ "$mode" != "always" ]; then
    log "FAIL archiver: archive_mode is '$mode'"
    return 1
  fi
  if ! [ "$archived_age" -eq "$archived_age" ] 2>/dev/null; then
    log "FAIL archiver: unreadable age '$archived_age' from pg_stat_archiver"
    return 1
  fi
  if [ "$archived_age" -lt 0 ]; then
    log "FAIL archiver: no WAL segment has ever been archived"
    return 1
  fi
  if [ "$failed_newer" = "1" ]; then
    log "FAIL archiver: last_failed_time is newer than last_archived_time"
    return 1
  fi

  # Age alone is not a fault: Postgres does not switch segments while nothing is
  # being written, so an idle database's last archive recedes with no WAL at risk.
  status_dir="$DATA_DIR/pg_wal/archive_status"
  if [ ! -d "$status_dir" ]; then
    log "FAIL archiver: cannot read $status_dir"
    return 1
  fi
  pending=$(find "$status_dir" -maxdepth 1 -name '*.ready' 2>/dev/null | wc -l)

  if [ "$pending" -eq 0 ]; then
    log "ok archiver: nothing waiting, last archived ${archived_age}s ago"
    return 0
  fi
  if [ "$archived_age" -gt "$ARCHIVE_MAX_AGE" ]; then
    log "FAIL archiver: ${pending} segment(s) waiting, last archived ${archived_age}s ago, limit ${ARCHIVE_MAX_AGE}s"
    return 1
  fi
  log "ok archiver: ${pending} segment(s) waiting, last archived ${archived_age}s ago"
}

check_base_backup() {
  local newest newest_epoch age now
  newest=$(timeout 30s wal-g backup-list --detail --json 2>/dev/null \
    | python3 -c 'import sys,json;b=json.load(sys.stdin);print(max(x["time"] for x in b) if b else "")') \
    || { log "FAIL base backup: wal-g backup-list failed or timed out"; return 1; }

  if [ -z "$newest" ]; then
    log "FAIL base backup: no base backup exists"
    return 1
  fi

  now=$(date -u +%s)
  newest_epoch=$(date -u -d "$newest" +%s) \
    || { log "FAIL base backup: could not parse backup timestamp '$newest'"; return 1; }
  age=$(( now - newest_epoch ))
  if [ "$age" -gt "$BACKUP_MAX_AGE" ]; then
    log "FAIL base backup: newest is ${age}s old, limit ${BACKUP_MAX_AGE}s"
    return 1
  fi
  log "ok base backup: newest is ${age}s old"
}

check_dump() {
  local newest age now
  newest=$(find "$DUMP_DIR" -type f -name '*.sql.gz' -printf '%T@\n' 2>/dev/null | sort -rn | head -1)
  if [ -z "$newest" ]; then
    log "FAIL dump: no dump found under $DUMP_DIR"
    return 1
  fi
  now=$(date -u +%s)
  age=$(( now - ${newest%.*} ))
  if [ "$age" -gt "$BACKUP_MAX_AGE" ]; then
    log "FAIL dump: newest is ${age}s old, limit ${BACKUP_MAX_AGE}s"
    return 1
  fi
  log "ok dump: newest is ${age}s old"
}

check_disk() {
  local used free
  used=$(df --output=pcent "$DATA_DIR" 2>/dev/null | tail -1 | tr -dc '0-9') \
    || { log "FAIL disk: df failed for $DATA_DIR"; return 1; }
  if ! [ "$used" -ge 0 ] 2>/dev/null; then
    log "FAIL disk: df returned no usable percentage for $DATA_DIR"
    return 1
  fi
  free=$(( 100 - used ))
  if [ "$free" -lt "$DISK_FREE_MIN" ]; then
    log "FAIL disk: ${free}% free, minimum ${DISK_FREE_MIN}%"
    return 1
  fi
  log "ok disk: ${free}% free"
}

while true; do
  ok=1
  check_archiver   || ok=0
  check_base_backup || ok=0
  check_dump       || ok=0
  check_disk       || ok=0

  if [ "$ok" = "1" ]; then
    if [ -n "${INSTATUS_HEARTBEAT_URL:-}" ]; then
      if curl -fsS --max-time 15 -o /dev/null "$INSTATUS_HEARTBEAT_URL"; then
        log "all checks passed, heartbeat sent"
      else
        log "all checks passed, but the heartbeat GET failed"
      fi
    else
      log "all checks passed, INSTATUS_HEARTBEAT_URL unset, nothing pinged"
    fi
  else
    log "one or more checks failed, heartbeat withheld"
  fi

  sleep "$INTERVAL"
done
