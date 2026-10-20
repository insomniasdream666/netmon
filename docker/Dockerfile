# NetMon container image.
#
# Multi-stage build: dependencies are compiled in the builder, then only the
# virtual environment and application sources are copied into the slim runtime
# image, which runs as a non-root user.
#
#   docker build -f docker/Dockerfile -t netmon .
#   docker run --rm -p 8080:8080 -e INFLUX_TOKEN=... netmon
#
# The image runs the web interface by default; override the command to run the
# TUI (requires an interactive TTY) or headless mode.

# ---------------------------------------------------------------------------
# Stage 1: build dependencies
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY pyproject.toml README.md ./
COPY netmon ./netmon

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install .

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    NETMON_ENV=production \
    NETMON_WEB_HOST=0.0.0.0 \
    NETMON_WEB_PORT=8080 \
    NETMON_SQLITE_PATH=/data/config.db

# Runtime tools NetMon shells out to. nmap and openssl are required for the
# port-scan and certificate collectors; iproute2/iputils provide ip/ss/ping.
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 \
        iputils-ping \
        nmap \
        openssl \
        dnsutils \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /usr/sbin/nologin netmon \
    && mkdir -p /data && chown netmon:netmon /data

COPY --from=builder /opt/venv /opt/venv
COPY --chown=netmon:netmon netmon /app/netmon
COPY --chown=netmon:netmon docs /app/docs
COPY --chown=netmon:netmon pyproject.toml README.md /app/

WORKDIR /app
USER netmon

VOLUME ["/data"]
EXPOSE 8080

# The web dashboard exposes /api/health, so use it as the container healthcheck.
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import httpx,sys; sys.exit(0 if httpx.get('http://127.0.0.1:8080/api/health', timeout=5).status_code < 400 else 1)"

CMD ["python", "-m", "netmon", "--web"]
