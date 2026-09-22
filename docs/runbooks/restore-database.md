# Restoring the production database

The production database is self-hosted Postgres 17 with WAL-G continuous archiving to Cloudflare R2.
Its definition is `compose.db.yml` and `pg-walg/` in this repo, run as project `voltius-db`; on the
production host it lives in `/home/ubuntu/fourretout/voltius-db/`. Three independent paths write to
the bucket:

- WAL-G base backups, daily (`BASEBACKUP_INTERVAL=86400`), pruned to the last 14 (`wal-g delete retain FULL`).
- WAL-G WAL archiving, `archive_timeout=60`, so the recovery point objective is ≤ 60 s.
- A nightly `pg_dump`, kept 7 daily / 4 weekly / 6 monthly, mirrored to R2 by rclone.

A backup nobody has restored is not a backup. Run the drill below at least quarterly, and after any
change to the stack, Postgres major version, or WAL-G version.

## Safety rules for a drill

The drill instance reads the same R2 prefix as production. Getting this wrong corrupts the archive
that production depends on.

- Start it with **`archive_mode=off`**. A promoted copy with archiving on pushes its own timeline-2
  WAL into production's archive.
- Never run `wal-g backup-push` or `wal-g delete` from the drill container.
- Do not attach it to the `cloudflare` network and do not publish a port. Nothing should be able to
  reach it, and it must not answer to the name `voltius-db`.
- Use a throwaway volume, and delete the volume afterwards. The drill data is a full copy of
  production, including user records.

## Drill

Read-only inventory first:

```sh
docker run --rm --env-file /home/ubuntu/fourretout/voltius-db/.env.db pg-walg:17-3.0.8 bash -c '
export AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY" \
  AWS_ENDPOINT="$R2_ENDPOINT" AWS_S3_FORCE_PATH_STYLE=true AWS_REGION="${AWS_REGION:-auto}" \
  WALG_COMPRESSION_METHOD=lz4
wal-g backup-list --detail'
```

The newest base backup should be under 24 hours old. The stack's `.env.db` supplies the R2 credentials
as `R2_*`; WAL-G reads `AWS_*`, which is why every command re-exports them.

Fetch the latest base into a scratch volume:

```sh
docker volume create waldrill-data
docker run --rm --env-file /home/ubuntu/fourretout/voltius-db/.env.db -v waldrill-data:/pgdata pg-walg:17-3.0.8 bash -c '
export AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY" \
  AWS_ENDPOINT="$R2_ENDPOINT" AWS_S3_FORCE_PATH_STYLE=true AWS_REGION="${AWS_REGION:-auto}" \
  WALG_COMPRESSION_METHOD=lz4
wal-g backup-fetch /pgdata LATEST
touch /pgdata/recovery.signal
cat >> /pgdata/postgresql.auto.conf <<CONF
restore_command = '"'"'wal-g wal-fetch "%f" "%p"'"'"'
recovery_target_timeline = '"'"'latest'"'"'
recovery_target_action = '"'"'promote'"'"'
archive_mode = '"'"'off'"'"'
CONF
chown -R postgres:postgres /pgdata && chmod 700 /pgdata'
```

For point-in-time recovery instead of end-of-WAL, add `recovery_target_time` and pick the base with
`wal-g backup-fetch /pgdata LATEST_MODIFIED_BEFORE=<timestamp>` or an explicit backup name.

Start it in recovery. The `restore_command` runs as a child of the postmaster, so the R2 credentials
must be in the container's environment, not only in the fetch step:

```sh
docker run -d --name waldrill --env-file /home/ubuntu/fourretout/voltius-db/.env.db \
  -v waldrill-data:/var/lib/postgresql/data --entrypoint bash pg-walg:17-3.0.8 -c '
export AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY" \
  AWS_ENDPOINT="$R2_ENDPOINT" AWS_S3_FORCE_PATH_STYLE=true AWS_REGION="${AWS_REGION:-auto}" \
  WALG_COMPRESSION_METHOD=lz4
exec docker-entrypoint.sh postgres -c archive_mode=off -c listen_addresses=localhost'
```

Watch for the four lines that matter, in order: `consistent recovery state reached`, `redo done at`,
`last completed transaction was at log time` — the real recovery point — `selected new timeline ID`,
then `database system is ready to accept connections`.

## Verify

```sh
docker exec waldrill bash -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -t -A -c "
  select count(*) from pg_tables where schemaname = '"'"'public'"'"';
  select max(version), count(*) filter (where not success) from _sqlx_migrations;"'
```

`pg_stat_user_tables.n_live_tup` reads 0 on a fresh restore because the statistics file is not
carried in the base backup. Use `count(*)` or relation sizes, not the stats view.

Cross-check the WAL-G result against the independent dump path, which shares no code with it:

```sh
zcat /home/ubuntu/fourretout/voltius-db/backups/last/voltius-latest.sql.gz \
  | grep -oE '^CREATE TABLE public\.[a-z_]+' | sed 's/.*public\.//' | sort
```

Tear down, including the volume:

```sh
docker rm -f waldrill && docker volume rm waldrill-data
```

## Last drill: 2026-09-22

Passed, against `base_00000001000000370000008E` (2026-09-21 21:48 UTC), using the `db` target built
from this repo (PostgreSQL 17.11, glibc 2.41-12+deb13u4) on data written by the previous image
(17.10, deb13u3), capped at `--cpus=1`.

| Measure | Result |
|---|---|
| Base fetch | 6 s, 78 MB on disk |
| WAL replay to end of archive | 37 s |
| Total to accepting connections | ~49 s |
| Recovery point reached | newest `updated_at` equal to production's at the time of the drill |
| Schema | 32 tables, migration 42, 0 failed |
| Size | 57 MB |
| Collation | `datcollversion` 2.41 = actual on every database |
| Index integrity | `bt_index_check(heapallindexed)` passed on all 141 btree indexes (24 on text) |
| Cross-check | table set identical to the nightly `pg_dump` |

Production was untouched: no port published, not on the `cloudflare` network, `archive_mode=off`,
and `voltius-db` stayed healthy throughout.

Recovery-time objective for the data is therefore about two minutes. The real outage window in a
host-loss scenario is dominated by provisioning a replacement host and restoring `.env.dockhand`,
neither of which this drill covers.
