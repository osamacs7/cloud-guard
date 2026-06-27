FROM python:3.12-slim AS base

RUN groupadd --gid 1000 appuser && \
    useradd --uid 1000 --gid 1000 --shell /bin/bash --create-home appuser

WORKDIR /app

FROM base AS builder

COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir build && \
    python -m build --wheel && \
    pip install --no-cache-dir dist/*.whl

FROM base AS production

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/cloud-guard /usr/local/bin/cloud-guard
COPY --from=builder /usr/local/bin/uvicorn /usr/local/bin/uvicorn
COPY policies/ policies/
COPY alembic/ alembic/
COPY alembic.ini .

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health').raise_for_status()"

CMD ["uvicorn", "cloud_guard.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
