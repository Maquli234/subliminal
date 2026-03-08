# ─── Build stage ───────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml .
COPY subliminal/ subliminal/

RUN pip install --no-cache-dir build \
 && python -m build --wheel --outdir /dist

# ─── Runtime stage ─────────────────────────────────────────────────────────────
FROM python:3.12-slim

LABEL org.opencontainers.image.title="SUBLIMINAL"
LABEL org.opencontainers.image.description="Passive & active subdomain reconnaissance"
LABEL org.opencontainers.image.source="https://github.com/Maquli/subliminal"

RUN addgroup --gid 1001 subliminal \
 && adduser --uid 1001 --gid 1001 --no-create-home --disabled-password subliminal

COPY --from=builder /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

USER subliminal
ENTRYPOINT ["subliminal"]
CMD ["--help"]
