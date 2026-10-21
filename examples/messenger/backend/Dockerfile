# The messenger: the web app built, then the backend serving it. Build context: the repository root
FROM node:24-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5 AS web
WORKDIR /web
COPY examples/messenger/frontend/package.json examples/messenger/frontend/package-lock.json ./
RUN npm ci
COPY examples/messenger/frontend/ ./
RUN npm run build

FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
COPY --from=ghcr.io/astral-sh/uv:0.12.21@sha256:a7aed3216253ee804de3e2d8afa5073baa1a177335345d43845cd4165e43b711 /uv /usr/local/bin/uv
WORKDIR /ms/backend
COPY examples/messenger/backend/pyproject.toml examples/messenger/backend/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY examples/messenger/backend/ ./
COPY examples/messenger/db/ /ms/db/
COPY --from=web /web/dist /ms/frontend/dist
ENV PATH=/ms/backend/.venv/bin:$PATH
# migrations and the policy first, as the database owner; then the app, as ms_app
CMD ["sh", "-c", "python /ms/db/migrate.py && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
