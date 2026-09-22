# Ansible

Makes a fresh machine a voltius host, and moves production onto it. Replaces
`scripts/bootstrap-host.sh`, which was never run end to end and had two faults this
does not: it wrote systemd units without `sudo` while refusing to run as root, and it
started `dump-mirror` against an empty `backups/`, whose first `rclone sync` deletes
every mirrored dump in R2.

Requires `ansible-core` on the controller. No collections, no Python modules on the
targets: every docker step is the CLI.

Nothing here is tied to a cloud. A target is any Ubuntu 24.04 host reachable over SSH —
`infra/oci` creates the one production happens to run on, and `infra/README.md` says
what a host from anywhere else has to satisfy.

## Inventory

Copy `inventory.example.yml` to `inventory.yml` (gitignored) and give each host its
private address. The controller is whichever machine holds `voltius-tofu` — its
OpenTofu state is the one that matters.

## Prepare a host

```sh
ansible-playbook site.yml -l newhost
```

Installs docker, age and rclone, creates the `cloudflare` network on the fixed
`172.22.0.0/16` (`TRUSTED_PROXIES` names it), lays out the sparse checkouts, builds the
pg-walg images and installs the connector compose file. It refuses to touch a host
where `voltius-server` is running, starts nothing, and reports which secret files are
still missing.

## Rehearse

```sh
ansible-playbook rehearse.yml -e voltius_target=rehearsal
# or, without a terminal to paste into:
ansible-playbook rehearse.yml -e voltius_target=rehearsal -e voltius_age_key_file=/dev/shm/age.key
```

Unpacks the secrets bundle, restores production into a throwaway volume, counts the
tables and migrations, then deletes the copy and the secrets. **`archive_mode=off`
throughout**, and no base-backup, backup-watch, dump, dump-mirror, server or tunnel: a
rehearsal must not write to R2 or answer to the world. It refuses to run on a host that
has a `voltius-server` container.

### Last migration drill: 2026-09-22

Phases 1–6 run between two throwaway A1 instances, production untouched: freeze,
`pg_switch_wal`, archive wait, source stack stopped, restore, promote, server started. The
target came up with 32 tables, 335 users, migration 42, on timeline 3, answering `/health`.
It took five attempts, and each failure was a fault worth finding — see PR #53.

Phase 7 is still unproven and cannot be drilled: pointing `api.voltius.app` somewhere is
the one step with no throwaway equivalent.

### Last rehearsal: 2026-09-22

Passed on a throwaway 1 OCPU / 6 GB A1 instance created by `var.hosts`, from bare Ubuntu 24.04:
`site.yml`, then a restore of production out of R2 — 32 tables, migration 42, 0 failed, matching
the manual drill. Production was untouched: `archive_mode=off`, nothing that writes to R2 started,
and the source host was never contacted. The instance was destroyed afterwards.

## Drill the move itself

`rehearse.yml` proves a host can be built and a backup restored. It does not prove
`migrate.yml`, whose freeze, WAL handover and cutover only ever run during a real move.
To run those without users noticing, migrate two throwaway hosts:

```sh
tofu apply   # var.hosts: drill-a and drill-b
ansible-playbook site.yml -l 'drill-a,drill-b'
ansible-playbook drill-seed.yml -e voltius_target=drill-a \
  -e voltius_age_key_file=/dev/shm/age.key -e voltius_drill_prefix=voltius-drill
ansible-playbook migrate.yml -e voltius_source=drill-a -e voltius_target=drill-b \
  -e voltius_cutover=false
```

`drill-seed.yml` reads production's prefixes exactly once, for the base backup that seeds
drill-a, then repoints that host under `voltius-drill/` and asserts none of production's
prefixes is named any more. The isolation is by prefix rather than by bucket because the
R2 credentials are scoped to one bucket and cannot write to another. The watchdog
heartbeat is cleared, so a drill cannot report production healthy.

`-e voltius_cutover=false` leaves `api.voltius.app` alone, which means phase 7 is the one
step a drill cannot prove. Destroy both hosts and empty the drill bucket afterwards.

## Move production

```sh
ansible-playbook migrate.yml -e voltius_source=oracle -e voltius_target=newhost
```

Eight phases; downtime runs from 4 to 7 and is about five minutes.

1. Preflight: source healthy, backups listed, target prepared, idle and roomy.
2. Secrets: prompts for the age key, unpacks the bundle on the target, deletes the key.
   The key is written to `/dev/shm` and nowhere else.
3. Copies `backups/` to the target, before anything can sync an empty directory.
4. **Downtime starts.** Stops the server, closes the WAL segment, waits for the
   archiver to catch up, then stops the source database stack **for good**.
5. Restores the newest base plus WAL onto the target and promotes it.
6. Starts the server and the connector there.
7. `tofu apply -var api_tunnel=voltius-api` points `api.voltius.app` at the new host's
   tunnel. **Downtime ends.**
8. Waits for the backup watchdog's first heartbeat.

The source database stack must stay stopped. Once the target promotes, both would
archive to the same R2 prefix, on diverging timelines.

## Rollback

Before phase 7: start `voltius-server` on the source again. Nothing has moved.

After phase 7: `tofu apply -var api_tunnel=oracle` and start the source stack — but
every write made on the target since the cutover is lost. Past a few minutes, roll
forward instead.
