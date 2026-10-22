# The services the conformance suites start beside Postgres (pooler.sh: PgBouncer), a stage each, pinned by digest
# as the other images are (Dependabot moves the digests). Never built: the scripts read each stage's image by its
# name.
FROM edoburu/pgbouncer:v1.26.0-p0@sha256:b17551c776ef7e5769ef80b956d20f85e2fd25dd8912d31d58f782aad495b711 AS pgbouncer
