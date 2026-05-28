# syntax=docker/dockerfile:1

FROM ghcr.io/astral-sh/uv:python3.14-alpine

# uv configuration: compile bytecode for faster startup, copy (not link)
# packages out of the build cache, and keep the managed venv at /app/.venv.
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

# Install dependencies first, using only the lockfile + manifest so this
# layer is cached until the dependency set actually changes.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --no-dev

# Now bring in the application and install it into the venv.
COPY pyproject.toml uv.lock README.md dmarc_to_discord.py ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev

# Run unprivileged.
RUN adduser -S -H -u 10001 appuser
USER appuser

# Bind to all interfaces inside the container
ENV LISTEN_HOST=0.0.0.0 \
    LISTEN_PORT=8080
EXPOSE 8080

ENTRYPOINT ["dmarc-to-discord"]
