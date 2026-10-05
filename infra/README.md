# infra

OpenTofu for the things outside a host: DNS and the tunnels (`cloudflare/`), and the
machines themselves (`oci/`, `hetzner/`).

Only the machine is provider-specific, and only for creating it. `ansible/` never
mentions a cloud: it takes any Ubuntu 24.04 host reachable over SSH and makes it a
voltius host. `oci/` is here because production runs on Oracle's free tier, and it is a
worked example of that one step, not a requirement.

## Using another provider

Write the equivalent of `oci/` for it — Hetzner, a VPS, a machine you own — and keep
everything else. What the host has to satisfy:

| | |
|---|---|
| OS | Ubuntu 24.04, aarch64 or x86-64 (the server image is multi-arch) |
| RAM | 4 GB or more |
| Disk | your database, its WAL and one base backup, with room to grow |
| Network | SSH from the controller; outbound to GHCR, R2 and Cloudflare |
| Inbound | none. Traffic arrives through the tunnel, so no port need be exposed |

Then `ansible-playbook site.yml -l <host>` and `migrate.yml` behave exactly as they do
on OCI.

`hetzner/` is that equivalent for Hetzner Cloud, rehearsed on 2026-10-05. Prefer an arm64
(CAX) type; x86 was proven to work for this database (`hetzner/README.md`).
