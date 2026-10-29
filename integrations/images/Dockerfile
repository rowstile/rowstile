# The services the conformance suites start beside Postgres (pooler.sh: PgBouncer), a stage each, pinned by digest
# as the other images are (Dependabot moves the digests). Never built: the scripts read each stage's image by its
# name.
FROM edoburu/pgbouncer:v1.26.0-p0@sha256:b17551c776ef7e5769ef80b956d20f85e2fd25dd8912d31d58f782aad495b711 AS pgbouncer
# Redis, the queues' broker for the background jobs (fastapi/test.sh: Celery's and RQ's workers)
FROM redis:8.10.3-alpine@sha256:21090af93f8324db2f0f0f4f38a7c60369d47d917e000c3423d89d2ae2883537 AS redis
