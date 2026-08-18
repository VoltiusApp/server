# Voltius Server

Axum/Rust API server for Voltius. Licensed under **AGPLv3** — see [LICENSE](./LICENSE).

## Self-Hosting

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/deploy/voltius-server?referralCode=_euqa6&utm_medium=integration&utm_source=template&utm_campaign=voltius-server)

```bash
cp .env.example .env
# Edit .env with your values
docker compose up -d
```

Listening on `http://0.0.0.0:14372` by default (override with `HOST_PORT` in `.env`).

Business customers who self-host receive a **commercial license exception** alongside their subscription, allowing private modifications without AGPLv3 obligations. See [COMMERCIAL_LICENSE.md](./COMMERCIAL_LICENSE.md).

Full self-hosting guide (env vars, reverse proxy, admin dashboard, updating) — [docs.voltius.app/self-hosting](https://docs.voltius.app/self-hosting/).
