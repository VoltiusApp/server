# Working on voltius-server

## No new cross-request in-process state

Anything that must be visible to more than one request — fan-out, presence, counters, caches
with correctness meaning — goes in Postgres, not in a `DashMap`, a `broadcast::channel` or a
`Mutex<HashMap>` on the app.

This server cannot run as more than one instance today, and four pieces of state are why:

| State | Where | What a second instance does |
|---|---|---|
| `SyncNotifier` | `src/sync_notifier.rs` | a client on A never sees an event caused by B — stale, no error |
| `TerminalManager` | `src/terminal_manager.rs` | a shared session only works if every participant lands on the same instance |
| Rate limiters | `src/rate_limit.rs` | N instances means N times every limit, register and auth included |
| Presence/usage | `src/routes/presence.rs` | each instance sees only its own users |

Every one added between now and that migration is another item on it. Four is a weekend;
twelve is a rewrite. The rule costs nothing to follow and is what "designed so it *can* be
scaled" means in practice.

`src/single_instance.rs` enforces the consequence: a second process on the same database
refuses to start, because the alternative is two servers disagreeing in silence. Clear it with
`ALLOW_MULTIPLE_INSTANCES=true` only once the table above is empty.

State that is genuinely per-process and carries no correctness — a metrics handle, a cached
compiled regex — is fine.
