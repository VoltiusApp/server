# Monitoring and the backup heartbeat

Three independent mechanisms, none of which cover the others:

| Mechanism | Watches | From | Alerts by |
|---|---|---|---|
| Instatus status page | HTTP endpoints (`/health`, `/health/deep`, ...) | outside the box | probe failure → configured channels |
| `backup-watch` (`voltius-backup-watch`) | WAL archiving, base backup age, dump age, disk | inside the box, against Postgres and the filesystem | **silence** — a missed heartbeat GET |
| `/metrics` | request rate/latency, DB pool, `sync_blobs` size, build info | pulled on demand | nothing. It answers questions during an investigation; nothing scrapes or evaluates it on a schedule |

`backup-watch` exists specifically because none of the HTTP endpoints can see a stalled WAL-G
archiver or a full disk — every status-page probe stays green while the recovery point silently
ages. See "Deployment status" below: this mechanism is not live yet.

## Reading `/metrics`

```sh
curl -s -H "x-admin-key: $ADMIN_SECRET" https://sync.voltius.app/metrics
```

Gated by the same `require_admin_key` middleware as the admin API (`src/routes/metrics.rs`,
`src/auth/mod.rs`): wrong or missing `x-admin-key` → 401, `ADMIN_SECRET` unset on the server → 503.
Output is Prometheus text exposition (`text/plain; version=0.0.4`).

| Metric | Type | Labels | Answers |
|---|---|---|---|
| `voltius_http_requests_total` | counter | `method`, `path`, `status` | Which routes are taking traffic, and their status-code mix |
| `voltius_http_request_duration_seconds` | histogram | `method`, `path` | Latency distribution per route (buckets: 5, 10, 25, 50, 100, 250, 500ms, 1, 2.5, 5, 10s) |
| `voltius_db_pool_connections` | gauge | `state` (`in_use`, `idle`) | Is the pool exhausted, at the moment of the scrape |
| `voltius_sync_blobs_bytes` | gauge | — | On-disk size of `sync_blobs`, refreshed every 5 minutes |
| `voltius_build_info` | gauge, always `1` | `version`, `sha` | Which binary is running. `sha` reads `unknown` until `GIT_SHA` is wired into the Docker build — it is not yet |

`path` is the route pattern (`/v1/users/:id`), never the raw request URI — user and object ids
never become label values (`src/observability.rs`).

All of these are counters and gauges since **process start**: nothing scrapes them on a schedule,
so a `curl` five minutes after a restart shows five minutes of traffic, not history. There is no
dashboard. Reading `/metrics` is for an investigation already underway, not for noticing one.

## `/health` versus `/health/deep`

- `GET /health` — `src/routes/health.rs`, returns the literal string `ok`, never touches Postgres.
  This is the container healthcheck (`compose.prod.yml`) and it must stay static: if it queried
  Postgres, a transient database hiccup would mark the container unhealthy and Docker would
  restart a server process that was otherwise fine, turning a blip into an outage.
- `GET /health/deep` — runs `SELECT 1` against the pool, returns JSON
  (`{"database": "ok"|"unreachable", "pool_size": N, "pool_idle": N}`), 200 on success, 503 on
  failure.

The Instatus monitor currently pointed at `https://sync.voltius.app/health` must be repointed to
`/health/deep`. `/health` is a static string — the status page can read 100% uptime while the
database is completely unreachable. This repoint is an operator action in the Instatus dashboard;
nothing in this repo does it.

## The heartbeat

`voltius-backup-watch` (service `backup-watch` in `compose.db.yml`) loops every
`BACKUP_WATCH_INTERVAL` seconds (default 900 = 15 min, `.env.db.example`), runs four checks, and
`GET`s `INSTATUS_HEARTBEAT_URL` only if every check passes. A failing round withholds the ping and
logs which check failed — nothing pages on a single check by name, the alert is Instatus reporting
a missed heartbeat.

When creating the Instatus "Cron / Heartbeat" monitor, set its expected interval to match
`BACKUP_WATCH_INTERVAL` (15 min) and grace comfortably above it — one slow or delayed round should
not page before a real outage does. Creating this monitor is an operator action in the Instatus
dashboard; see "Deployment status" below for whether the service sending the pings is even running.

The four checks (`pg-walg/backup-watch.sh`):

| Check | Threshold | Env var (default) |
|---|---|---|
| `check_archiver` | `pg_stat_archiver.last_archived_time` under the limit **and** `last_failed_time` not newer than `last_archived_time` | `ARCHIVE_MAX_AGE_SECONDS` (600s) |
| `check_base_backup` | Newest `wal-g backup-list` entry under the limit | `BACKUP_MAX_AGE_SECONDS` (172800s / 48h) |
| `check_dump` | Newest `*.sql.gz` under `DUMP_DIR` under the limit | `BACKUP_MAX_AGE_SECONDS` (same, 48h) |
| `check_disk` | Free space on `DATA_DIR` at or above the minimum | `DISK_FREE_MIN_PERCENT` (15%) |

The archiver query runs with `PGCONNECT_TIMEOUT=10` and a 10s `statement_timeout`; the base-backup
check wraps `wal-g backup-list` in `timeout 30s`. A hung Postgres or a hung WAL-G call fails the
round instead of hanging the loop.

**`backup-watch` requires the Debian `PG_BASE`.** `pg-walg/Dockerfile` builds on either
`postgres:17-trixie` (Debian, the default) or `postgres:17-alpine`, but `check_base_backup` and
`check_dump` use `find -printf`, `date -d` and `check_disk` uses `df --output` — none of which
busybox provides on the Alpine base (`.env.db.example`). Building this image with
`PG_BASE=postgres:17-alpine` silently breaks `backup-watch` even though the container starts.

### The exit-127 archiver quirk — the age check is load-bearing

PostgreSQL does **not** update `pg_stat_archiver.last_failed_time` when `archive_command` fails
because the command itself could not be found (shell exit 127 — "command not found"). This was
found empirically on PostgreSQL 17.11 during verification of this script: removing the `wal-g`
binary entirely caused repeated logged archiver failures and postmaster respawns, but
`pg_stat_archiver.failed_count` and `last_failed_time` never moved, even after 40+ seconds and
several respawns. Only a command that runs and then exits non-zero updates those columns.

Practically: if the `wal-g` binary goes missing from the image (a bad rebuild, a regression in
`pg-walg/Dockerfile`), the "`last_failed_time` newer than `last_archived_time`" half of
`check_archiver` can never fire, no matter how long the binary stays missing. The **age check**
(`last_archived_time` older than `ARCHIVE_MAX_AGE_SECONDS`) is what catches that case, because no
WAL segment archives successfully either way. Do not rely on the failure-newer-than-success half
of this check on its own — it is confirmation when it fires, not the primary signal.

## When the heartbeat alerts

Triage order:

1. Read the log:
   ```sh
   docker logs --tail 50 voltius-backup-watch
   ```
2. Find the `FAIL` line — it names the check and the measured value, e.g.
   `FAIL archiver: last archived 900s ago, limit 600s`.
3. Apply the matching remedy:

   - **`FAIL archiver`** — WAL-G cannot reach R2, or the binary/command is broken (see the exit-127
     quirk above — an age failure with no failure-newer-than-success half still means the archiver
     is stuck). Check R2 credentials (`WALG_S3_PREFIX`, `AWS_*` / `R2_*` in `.env.db`) and:
     ```sh
     docker exec voltius-db psql -U voltius -d voltius -c "SELECT * FROM pg_stat_archiver;"
     ```
   - **`FAIL base backup`** — `voltius-base-backup` is wedged or its last `wal-g backup-push`
     failed. Check its own log:
     ```sh
     docker logs --tail 50 voltius-base-backup
     ```
   - **`FAIL dump`** — `voltius-dump` (the independent `pg_dump` path) or `voltius-dump-mirror`
     is wedged. Check both:
     ```sh
     docker logs --tail 50 voltius-dump
     docker logs --tail 50 voltius-dump-mirror
     ```
   - **`FAIL disk`** — find the consumer before deleting anything. WAL-G retention
     (`wal-g delete retain FULL`) runs inside `voltius-base-backup`'s own loop, not `backup-watch`;
     do not manually delete files under the data or backups volumes without confirming what still
     needs them.

If the underlying data is in doubt after resolving the alert, the restore drill in
`restore-database.md` proves whether it is actually recoverable — a heartbeat resuming does not by
itself prove that.

## Deployment status

`compose.db.yml` is in this repo but **is not adopted by the live stack**, which still runs its own
copy of the database compose file. `backup-watch` therefore **does not run in production** until
one of:

- the live stack is switched to `compose.db.yml`, or
- the `backup-watch` service is hand-added to the live copy.

Both touch production and are the operator's call — nothing in this task set does either. Until
one happens, there is no heartbeat, no missed-heartbeat alert, and the Instatus monitor described
above has nothing pinging it even once it exists. Check what is actually running before trusting
this document:

```sh
docker ps --filter name=voltius-backup-watch
```

See `restore-database.md` for the database stack's layout, the drill that proves a restore works,
and where the live copy currently lives.
