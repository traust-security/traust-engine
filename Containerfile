# ── Builder stage ───────────────────────────────────────────────────
# Hardened, RPM-based Python builder image from a public registry
# (registry.access.redhat.com needs no credentials). Pinned by digest.
#
# MUST stay on the same Python minor as the runtime stage below: the .venv
# built here is copied wholesale into the runtime, and native-extension .so
# files are ABI-pinned per minor while the venv's script shebangs hardcode
# the builder's interpreter path.
FROM registry.access.redhat.com/hi/python:3.12.16-builder@sha256:370dac28b556bdc990f9d04fc8d4ff5896bc5c412e49885f5e788b4c913b75f0 AS builder

ARG UV_VERSION=0.7

USER 0

# git is required for uv to resolve the traust-core commit pin. The
# repository is public and resolves without credentials.
RUN dnf install -y git ca-certificates \
  && dnf clean all

RUN pip install --no-cache-dir "uv>=${UV_VERSION}"

WORKDIR /app

# Dependency layer first — cache-friendly when only source changes.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY src/ ./src/
RUN uv build --wheel --out-dir /app/dist

# Install the built wheel into the venv so the runtime stage gets a
# single self-contained tree (traust-engine console script included).
RUN uv pip install --no-deps /app/dist/*.whl

# The engine's preflight requires gitleaks; the distroless runtime has no shell or
# package manager, so the binary ships in the image. It is a build input fetched to
# the repo root before building — never committed (.gitignore'd; the build context
# includes it through .containerignore's !gitleaks): the upstream v8.21.2
# linux-amd64 release artifact. The builder has a shell, so the digest is verified
# here and the runtime copy below refuses to ship anything else.
COPY gitleaks /tmp/gitleaks
RUN echo "50b742abd7daad8bbddb6301f3017efb680632d9a5b3b4d8f137b3aac250e359  /tmp/gitleaks" \
      | sha256sum -c - && chmod 0555 /tmp/gitleaks

# ── Runtime stage ───────────────────────────────────────────────────
# Minimal hardened Python runtime. Runs as a non-root user (UID 65532) by
# default and ships no package manager, so nothing is installed here.
# Python minor must match the builder stage above (see note there).
FROM registry.access.redhat.com/hi/python:3.12.16@sha256:92e83dcf087d5ef02e6edaf218ab40c297227b8845da97db8f6766b698703d74

# OCI labels. SOURCE_REVISION and VERSION are supplied by the build.
ARG SOURCE_REVISION=unknown
ARG VERSION=unknown
LABEL org.opencontainers.image.source="https://github.com/traust-security/traust-engine" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.title="traust-engine" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      name="traust-engine" \
      version="${VERSION}" \
      release="1" \
      vendor="Red Hat, Inc." \
      url="https://github.com/traust-security/traust-engine" \
      summary="traust continuous-ops service" \
      description="traust_engine.ops: the continuous-ops loop on a pack — admission, the tick and the reaper — on traust-core's services. Core config and pack are mounted at runtime (--core/--pack)." \
      distribution-scope="public" \
      com.redhat.component="traust-engine" \
      io.k8s.description="traust continuous-ops service (traust-engine)." \
      io.k8s.display-name="Traust Engine" \
      maintainer="Traust maintainers <traust@redhat.com>"

# License text at the absolute path certification tooling (HasLicense) reads.
COPY LICENSE /licenses/LICENSE

COPY --from=builder /app/.venv /app/.venv

# The engine's preflight requires gitleaks; the distroless runtime has no shell or
# package manager, so the binary ships in the image — the copy the builder stage
# above verified against the pinned v8.21.2 digest.
COPY --from=builder /tmp/gitleaks /usr/local/bin/gitleaks

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# The engine is a CLI loop, not a server: no port or liveness probe. Mount
# the core config and pack at runtime; set `home:` in core.yaml to a writable
# mounted path if persistent state is required.
ENTRYPOINT ["traust-engine"]
CMD ["--help"]
