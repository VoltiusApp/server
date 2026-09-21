# Postgres + WAL-G, for continuous WAL archiving and PITR to S3-compatible storage.
#
# Works on either base. Pick with PG_BASE, and read the note in .env.db.example
# first: glibc and musl sort text differently, so the choice is baked into every
# text index at initdb and cannot be changed under an existing data directory.
ARG PG_BASE=postgres:17-trixie

FROM alpine:3.22 AS walg
ARG WALG_VERSION=v3.0.8
ARG TARGETARCH
RUN set -eux; \
    apk add --no-cache curl; \
    # 20.04 is the oldest glibc upstream builds against (2.31), so it runs anywhere newer.
    case "${TARGETARCH:-$(apk --print-arch)}" in \
      amd64|x86_64)  arch=amd64 ;; \
      arm64|aarch64) arch=aarch64 ;; \
      *) echo "wal-g publishes no build for ${TARGETARCH:-$(apk --print-arch)}" >&2; exit 1 ;; \
    esac; \
    name="wal-g-pg-20.04-${arch}"; \
    url="https://github.com/wal-g/wal-g/releases/download/${WALG_VERSION}"; \
    cd /tmp; \
    curl -fsSL -O "${url}/${name}.tar.gz" -O "${url}/${name}.tar.gz.sha256"; \
    sha256sum -c "${name}.tar.gz.sha256"; \
    tar -xzf "${name}.tar.gz"; \
    install -m 0755 "${name}" /wal-g

FROM ${PG_BASE}
# wal-g publishes glibc binaries only; gcompat runs them on musl.
RUN set -eux; \
    if [ -f /etc/alpine-release ]; then \
      apk add --no-cache gcompat curl; \
    else \
      apt-get update && apt-get install -y --no-install-recommends curl python3 \
        && rm -rf /var/lib/apt/lists/*; \
    fi
COPY --from=walg /wal-g /usr/local/bin/wal-g
COPY backup-watch.sh /usr/local/bin/backup-watch
RUN chmod +x /usr/local/bin/backup-watch
RUN wal-g --version
