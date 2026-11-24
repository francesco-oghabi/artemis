# syntax=docker/dockerfile:1
#
# Runtime image (no compilation inside the image): install only common tools and drop in a precompiled Linux single binary.
# The binary is cross-compiled by CI's binaries job (pure Go, no QEMU) and placed, per target architecture, at
# dist/<TARGETARCH>/artemis in the build context. This way, for multi-arch builds, arm64 only emulates the apt layer
# and no longer emulates the Next/Go compilation, which is much faster.
#
# When building the image manually in local, prepare the binary yourself first:
#   cd web && npm run build:static && cd ..
#   cp -r web/out server/webui/dist
#   CGO_ENABLED=0 GOARCH=amd64 go build -tags embedui -o dist/amd64/artemis ./cmd/artemis
#   docker build -t artemis:local .
FROM python:3.12-slim-bookworm
ARG TARGETARCH
# Common tools: ripgrep / curl / vim, plus a set of recon staples (add or remove as needed).
# Install Node 20.x from NodeSource: bookworm's bundled apt nodejs is 18, and Playwright requires >=20.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates ripgrep curl wget vim git jq unzip \
      dnsutils iputils-ping netcat-openbsd whois nmap \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
# Preinstall Playwright MCP/CLI + Chromium so the in-container browser MCP works out of the box.
# Note: the previous layer cleared the apt lists, and `--with-deps` needs apt to install Chromium's system
# dependencies, so this layer runs apt-get update first to rebuild the lists; otherwise playwright install fails with exit 100.
RUN apt-get update \
    && npm install -g @playwright/mcp@latest @playwright/cli@latest playwright@latest \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*
# Report generation depends on python-docx (the Go side invokes report_builder.py as a subprocess when rendering .docx).
RUN pip install --no-cache-dir python-docx
WORKDIR /app
# The precompiled binary for the matching architecture (dist/amd64/artemis or dist/arm64/artemis).
COPY dist/${TARGETARCH}/artemis /app/artemis
RUN chmod +x /app/artemis
COPY skills/ /app/skills/
# data/ (SQLite + jwt.key) persistence point
VOLUME ["/app/data"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/artemis"]
CMD ["-addr", ":8787", "-proxy", ":8788"]
