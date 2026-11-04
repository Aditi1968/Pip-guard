# pip guard sandbox image (FR-4.7). Build from the repo root:
#   docker build -f sandbox/sandbox.Dockerfile -t pipguard-sandbox:dev .
# Runtime hardening (network, caps, read-only FS, limits) is applied by sandbox.py at
# `docker run`, not here; the image only provides a non-root user, strace and seeded files.
# Base pinned by digest (python:3.12-slim-bookworm, resolved 2026-11-02).
FROM python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337

RUN apt-get update \
    && apt-get install -y --no-install-recommends strace=6.1-0.1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin sandbox \
    && mkdir -p /sandbox/site-packages \
    && chown 10001:10001 /sandbox/site-packages

# Seeded credential files (FR-4.3), generated at build so no values live in git.
COPY sandbox/seed_credentials.py sandbox/manifest.json /opt/pipguard/
RUN python /opt/pipguard/seed_credentials.py /home/sandbox /opt/pipguard/manifest.json \
    && chown -R 10001:10001 /home/sandbox
COPY sandbox/runner.py /opt/pipguard/runner.py

ENV HOME=/home/sandbox \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_INPUT=1 \
    PIP_CACHE_DIR=/home/sandbox/.cache/pip \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/sandbox/site-packages

USER 10001:10001
WORKDIR /home/sandbox/project
CMD ["python", "-c", "print('pipguard sandbox')"]
