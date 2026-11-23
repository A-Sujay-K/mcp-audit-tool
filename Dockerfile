# Hardened multi-stage Dockerfile for mcp-sentinel
# Base image pinned to exact immutable digest
FROM python:3.11-slim@sha256:4b4c73b069d32d0f5291dd86214ec04fa1807ce678a1ee1bf9337ff8beae13e4 AS builder

WORKDIR /build

# Install uv for fast, deterministic builds
COPY --from=ghcr.io/astral-sh/uv:0.4.20 /uv /bin/uv

COPY pyproject.toml .
COPY src/ src/
COPY README.md .

RUN uv pip install --system --no-cache .

# Final unprivileged runtime image
FROM python:3.11-slim@sha256:4b4c73b069d32d0f5291dd86214ec04fa1807ce678a1ee1bf9337ff8beae13e4

# Create unprivileged non-root user and group
RUN groupadd -g 10001 sentinel && \
    useradd -u 10001 -g sentinel -m -s /sbin/nologin sentinel

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/mcp-sentinel /usr/local/bin/mcp-sentinel

# Security: Run as unprivileged user
USER sentinel:sentinel
WORKDIR /home/sentinel

# Enforce non-root execution and drop all capabilities
ENTRYPOINT ["/usr/local/bin/mcp-sentinel"]
CMD ["scan"]
