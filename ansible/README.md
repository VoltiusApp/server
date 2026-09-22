# Ansible

Makes a fresh machine a voltius host, and moves production onto it. Replaces
`scripts/bootstrap-host.sh`, which was never run end to end and had two faults this
does not: it wrote systemd units without `sudo` while refusing to run as root, and it
started `dump-mirror` against an empty `backups/`, whose first `rclone sync` deletes
every mirrored dump in R2.

Requires `ansible-core` on the controller. No collections, no Python modules on the
targets: every docker step is the CLI.

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
```

Unpacks the secrets bundle, restores production into a throwaway volume, counts the
tables and migrations, then deletes the copy and the secrets. **`archive_mode=off`
throughout**, and no base-backup, backup-watch, dump, dump-mirror, server or tunnel: a
rehearsal must not write to R2 or answer to the world. It refuses to run on a host that
has a `voltius-server` container.

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
