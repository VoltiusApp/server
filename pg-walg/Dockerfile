# Postgres + WAL-G, for continuous WAL archiving and PITR to S3-compatible storage.
#
# The base is pinned to a Debian suite, not to bare `postgres:17`, because glibc owns
# text collation: initdb bakes the host's collation into every text index, and moving
# an existing data directory to a different glibc can silently corrupt their ordering.
# Match the suite the cluster was initialised on, or dump and reload.
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
COPY --from=walg /wal-g /usr/local/bin/wal-g
RUN wal-g --version
