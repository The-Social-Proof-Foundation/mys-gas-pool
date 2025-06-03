FROM rust:1.82-bullseye AS chef
WORKDIR /mys
ARG GIT_REVISION
ENV GIT_REVISION=$GIT_REVISION
RUN apt-get update && apt-get install -y cmake clang curl gettext-base

# Build and cache all dependencies
FROM chef AS builder
WORKDIR /
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

# Production Image
FROM debian:bullseye-slim AS runtime
RUN apt-get update && apt-get install -y libjemalloc-dev ca-certificates curl gettext-base
COPY --from=builder /target/release/mys-gas-station /usr/local/bin/mys-gas-station

# Create config directory
RUN mkdir -p /etc/gas-station

# Copy configuration (which will be templated in place)
COPY gas-station-config.yaml /etc/gas-station/config.yaml

# Create startup script that substitutes environment variables
RUN echo '#!/bin/bash\\n\
set -e\\n\
# Set default values if not provided\\n\
export PORT=${PORT:-9527}\\n\
echo "Substituting environment variables in config..."\\n\
cat /etc/gas-station/config.yaml | envsubst > /etc/gas-station/config.tmp.yaml && mv /etc/gas-station/config.tmp.yaml /etc/gas-station/config.yaml\\n\
echo "Starting mys-gas-station..."\\n\
exec mys-gas-station --config-path /etc/gas-station/config.yaml' > /usr/local/bin/start.sh

RUN chmod +x /usr/local/bin/start.sh

ARG BUILD_DATE
ARG GIT_REVISION
LABEL build-date=$BUILD_DATE
LABEL git-revision=$GIT_REVISION

# Expose ports
EXPOSE 9527 9184

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:9527/ || exit 1

# Use startup script
CMD ["/usr/local/bin/start.sh"]