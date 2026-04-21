# Voltius Server

Axum/Rust API server for Voltius.

## Getting Started

```bash
docker compose up -d
```

Listening on `http://0.0.0.0:13140` by default.

## Environment Variables

Copy `.env.example` to `.env` and fill in the values.

```env
DATABASE_URL=postgres://user:pass@localhost/voltius
JWT_SECRET=at-least-32-bytes-of-random-data

# LemonSqueezy billing
LEMONSQUEEZY_SIGNING_SECRET=whsec_...
LS_VARIANT_PRO=000000
LS_VARIANT_TEAMS=000001

# CORS (comma-separated; empty = allow all)
CORS_ORIGINS=https://your-app.com,tauri://localhost

# Rate limiting
SYNC_RATE_LIMIT=60
TRUSTED_PROXY_IP=127.0.0.1

# Admin dashboard
ADMIN_SECRET=a-long-random-shared-secret
```

### Admin dashboard

`ADMIN_SECRET` is a shared secret between this server and the Next.js web app. The web app sends it as an `X-Admin-Key` header on every admin API request. It must match the `ADMIN_SECRET` set in `web/.env.local` (or Vercel environment variables).

Generate a secure value with:

```bash
openssl rand -hex 32
```

## Migrations

Migrations live in `migrations/` and are numbered sequentially. Run them with:

```bash
sqlx migrate run
```

| # | Description |
|---|---|
| 001 | users table |
| 002 | sync_blobs |
| 003 | teams + team_members |
| 004 | terminal_sessions |
| 005 | public terminal sessions |
| 006 | terminal session multi-vault |
| 007 | team vault sync |
| 008 | custom roles |
| 009 | backfill trial tier |
| 010 | admin/ban fields on users |
| 011 | user_feature_flags |
| 012 | admin_audit_log |
| 013 | churn_events |
