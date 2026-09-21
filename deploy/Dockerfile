# Gmail MCP Gateway
#
# Build from the repository root:
#   docker build -f deploy/Dockerfile -t gmail-mcp-gateway .
#
# The image contains no credentials. Google OAuth material and the encryption
# key live in a volume mounted at /secrets, which the MCP client never sees.

# --- build ------------------------------------------------------------------
# Pin both the Python base and uv version. Application dependencies come from
# uv.lock, so rebuilding the same commit does not silently pick newer packages.
FROM ghcr.io/astral-sh/uv:0.12.5@sha256:e85be844203885286c60ffad8a858d48afb6c5a5c237ca0e67f12e74b8f174b1 AS uv
FROM python:3.14.6-slim@sha256:7bec7ddcddeff7975d6ba9b4be7dd6f6b2f55e7491539145e2978f7f97ce9144 AS build

ENV PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /build
COPY --from=uv /uv /uvx /bin/
COPY pyproject.toml uv.lock README.md ./
COPY src ./src

RUN uv sync --frozen --no-dev --no-editable

# --- runtime ----------------------------------------------------------------
FROM python:3.14.6-slim@sha256:7bec7ddcddeff7975d6ba9b4be7dd6f6b2f55e7491539145e2978f7f97ce9144 AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    GMAIL_MCP_CONFIG_DIR=/config \
    GMAIL_MCP_DATA_DIR=/data \
    GMAIL_MCP_SECRETS_DIR=/secrets \
    GMAIL_MCP_HTTP_HOST=0.0.0.0 \
    GMAIL_MCP_HTTP_PORT=8765 \
    GMAIL_MCP_ALLOW_REMOTE_BIND=true

# 0.0.0.0 inside a container is a container-local interface, not a public one.
# Publish the port only to 127.0.0.1 on the host (see docker-compose.yml), and
# note that a gateway bearer token is required regardless.

COPY --from=build /opt/venv /opt/venv

RUN useradd --system --uid 10001 --create-home --home-dir /home/gateway gateway \
 && mkdir -p /config /data /secrets \
 && chown -R gateway:gateway /config /data /secrets \
 && chmod 700 /data /secrets

USER gateway
WORKDIR /home/gateway

VOLUME ["/config", "/data", "/secrets"]
EXPOSE 8765

HEALTHCHECK --interval=60s --timeout=10s --start-period=10s --retries=3 \
    CMD ["gmail-mcp-gateway", "health"]

ENTRYPOINT ["gmail-mcp-gateway"]
CMD ["serve", "--transport", "http"]
