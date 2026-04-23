# Voltius Server

Axum/Rust API server for Voltius. Licensed under **AGPLv3** — see [LICENSE](./LICENSE).

## Self-Hosting

```bash
cp .env.example .env
# Edit .env with your values
docker compose up -d
```

Listening on `http://0.0.0.0:8080` by default.

Business customers who self-host receive a **commercial license exception** alongside their subscription, allowing private modifications without AGPLv3 obligations. See [COMMERCIAL_LICENSE.md](./COMMERCIAL_LICENSE.md).

## Environment Variables

Copy `.env.example` to `.env` and fill in the values. That file is the source of truth for all available variables.

Generate secure secrets with:

```bash
openssl rand -hex 32
```

### Admin dashboard

`ADMIN_SECRET` is a shared secret between this server and the Next.js web app. The web app sends it as an `X-Admin-Key` header on every admin API request. It must match the `ADMIN_SECRET` set in `web/.env.local` (or Vercel environment variables).

## Migrations

Migrations run automatically at server startup. No manual steps needed.
