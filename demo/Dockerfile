# VIRP demo container.
#
# Builds the reference implementation and runs demo/run.sh against a
# deterministic simulated target. No real device, credentials, or network
# access are involved.
#
# Build and run from the repository root:
#   docker compose -f demo/docker-compose.yml run --rm demo
#
# Copyright (c) 2026 Third Level IT LLC — Apache 2.0

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        git \
        ca-certificates \
        python3 \
        libssl-dev \
        libsodium-dev \
        libsqlite3-dev \
        libssh2-1-dev \
        libcurl4-openssl-dev \
        libjson-c-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /virp
COPY . /virp

# Build up front so `docker compose run` starts the demo immediately.
RUN make -s all && make -s prod

ENTRYPOINT ["./demo/run.sh", "--no-build"]
