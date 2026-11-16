# GuardHub API + worker + migrations image. Build context: repository root
# (it needs packages/shared for i18n/contracts and ops/migrations).
FROM python:3.12-slim AS build
ENV PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
RUN pip install uv==0.12.5
WORKDIR /app/apps/api
COPY apps/api/pyproject.toml apps/api/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY apps/api/guardhub_api ./guardhub_api
RUN uv sync --frozen --no-dev

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH=/app/apps/api/.venv/bin:$PATH
RUN groupadd --system --gid 10001 guardhub \
 && useradd --system --uid 10001 --gid guardhub --no-create-home --shell /usr/sbin/nologin guardhub
WORKDIR /app/apps/api
COPY --from=build /app/apps/api /app/apps/api
COPY packages/shared /app/packages/shared
COPY ops/migrations /app/ops/migrations
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "guardhub_api.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", "--no-proxy-headers"]
