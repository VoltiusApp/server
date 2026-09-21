# Deploying voltius-server

Production runs on the same host as the database, as the `voltius-server` container in the
`voltius` compose project, behind a Cloudflare tunnel. The image comes from GHCR; the host does
not compile Rust.

Merging or pushing a commit does not change production. Only a pull + recreate does.

## Where things live

| Thing | Location |
|---|---|
| Deployment tree | `/var/lib/docker/volumes/dockhand_dockhand_data/_data/stacks/Docker/voltius` |
| Compose project | `-p voltius -f compose.prod.yml` |
| Environment | `.env.dockhand` in that tree (untracked, never in git, must survive every operation) |
| Image | `ghcr.io/voltiusapp/voltius-server:sha-<short>` |

The tree is root-owned and `/var/lib/docker` is `0710`, so every command runs as
`sudo sh -c 'cd <tree> && …'`. A plain `cd` fails. Read the path back off the container rather than
trusting this document:

```sh
docker inspect voltius-server --format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}'
```

## Images

`.github/workflows/docker.yml` publishes on every push to `main`: `latest`, `sha-<short>`, and the
branch name, as one multi-arch manifest covering `linux/amd64` and `linux/arm64`.

Deploy `sha-<short>`, never `latest`. `latest` is mutable and overlapping pushes race on it, so
`latest` cannot be rolled back to and cannot be reasoned about after the fact.

`SERVER_TAG` in `.env.dockhand` selects the tag. `compose.prod.yml` refuses to start without it.

## Deploy

1. Pick the commit and confirm the image exists with both architectures:

   ```sh
   SHA=$(git -C /home/ubuntu/fourretout/voltius-dev/server rev-parse --short=7 origin/main)
   docker buildx imagetools inspect ghcr.io/voltiusapp/voltius-server:sha-$SHA
   ```

2. Review what actually changes, including migrations:

   ```sh
   git -C /home/ubuntu/fourretout/voltius-dev/server diff --stat <deployed-sha>..$SHA
   ```

   `main` is the integration branch for this repo — `dev` is abandoned. Migrations run
   automatically at startup via `sqlx::migrate!`, so a migration in the diff means the recreate
   also changes the schema. Confirm it is forward-compatible with the currently deployed binary,
   because a rollback will not undo it.

3. Pull first, so the download is not part of the outage window:

   ```sh
   sudo sh -c 'cd <tree> && SERVER_TAG=sha-'$SHA' docker compose -p voltius --env-file .env.dockhand -f compose.prod.yml pull server'
   ```

4. Record the tag you are leaving, for rollback, then set the new one in `.env.dockhand`:

   ```sh
   sudo sh -c 'cd <tree> && grep ^SERVER_TAG .env.dockhand'
   ```

   Edit `SERVER_TAG=sha-<new>` in place. Do not rewrite the file wholesale; it holds every
   production secret.

5. Recreate and wait for health:

   ```sh
   sudo sh -c 'cd <tree> && docker compose -p voltius --env-file .env.dockhand -f compose.prod.yml up -d server'
   docker inspect voltius-server --format '{{.State.Health.Status}}'
   ```

   `--env-file` is required. Without it compose prints a wall of "variable is not set" warnings and
   starts the server with empty secrets, which fails at the first authenticated request rather than
   at startup.

## Verify

```sh
curl -fsS http://127.0.0.1:14372/health
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:14372/v1/billing/subscription
```

`/health` must return 200. The unauthenticated billing call must return **401**: 401 proves the
route is registered and the secrets loaded, 404 means the route is missing from this image, and 500
means a secret is blank.

Confirm the image the container is actually running matches the manifest digest from step 1:

```sh
docker inspect voltius-server --format '{{.Image}}'
```

If a migration shipped, confirm it applied:

```sh
docker exec voltius-db psql -U voltius -d voltius -t \
  -c "SELECT version, description, success FROM _sqlx_migrations ORDER BY version DESC LIMIT 2;"
```

## Rollback

Set `SERVER_TAG` back to the previous `sha-<short>` and repeat steps 3 and 5. The old image is
already in the local cache, so this is seconds.

A rollback reverts the binary, never the schema. If the deploy applied a migration, the older
binary must still work against the new schema — which is the reason to check that before deploying,
not after.

## First cutover from the old local-build setup

Before the first GHCR deploy the tree built the image itself with `build: .`. To cut over:

1. Confirm the tree's tracked files are clean and at the commit whose image you are about to
   deploy. `git status --porcelain` in the tree shows untracked leftovers (`.env.dockhand` and its
   backups, `build.rs`, orphan `src/*.rs` files); those are expected and are not copied into a
   CI-built image.
2. Keep the last locally built image as a fallback: `docker tag voltius-server:latest voltius-server:pre-ghcr-<date>`.
3. Add `SERVER_TAG=sha-<short>` to `.env.dockhand`.
4. Update `compose.prod.yml` in the tree to this repo's version (`image:` instead of `build: .`).
5. Deploy as above.

Local builds took 13–17 minutes on this host's 2 cores, competing with the running server for CPU
the whole time. CI finishes sooner and the host no longer needs a Rust toolchain or a build cache.
