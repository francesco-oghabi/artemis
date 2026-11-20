#!/usr/bin/env bash
# Build the local `artemis:custom` image from source and restart the service.
#
# Uses the project's self-contained Dockerfile.build, which compiles the frontend
# (Next static export) and the Go binary entirely inside containers, embedding the
# UI (go:embed all:webui/dist) and the skill library (go:embed all:skillsdist,
# report-generation excluded) into a single linux/amd64 binary. No Go/Node needed
# on the host. The runtime Dockerfile then copies that prebuilt binary.
#
# Steps (== Dockerfile.build header + docker-compose.override pins artemis:custom):
#   1. build + export the binary to dist/<arch>/artemis
#   2. docker build -t artemis:custom .   (runtime image around the binary)
#   3. docker compose up -d artemis        (restart with the new image)
set -euo pipefail
cd "$(dirname "$0")/.."

ARCH="${ARCH:-amd64}"

echo "[1/3] Compile UI + binary (embedui) via Dockerfile.build -> dist/$ARCH/artemis"
docker build -f Dockerfile.build --output "type=local,dest=dist/$ARCH" .

echo "[2/3] Build runtime image artemis:custom"
docker build -t artemis:custom .

echo "[3/3] Restart service (compose.override pins image: artemis:custom)"
docker compose up -d artemis

echo "Done. artemis:custom rebuilt and restarted."
