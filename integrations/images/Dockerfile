# The services the conformance suites start beside Postgres (pooler.sh: PgBouncer), a stage each, pinned by digest
# as the other images are (Dependabot moves the digests). Never built: the scripts read each stage's image by its
# name.
FROM edoburu/pgbouncer:v1.26.0-p0@sha256:b17551c776ef7e5769ef80b956d20f85e2fd25dd8912d31d58f782aad495b711 AS pgbouncer
# Neon's WebSocket proxy, for its serverless driver in front of a plain Postgres (nextjs/test.sh); it is published
# as latest only
FROM ghcr.io/neondatabase/wsproxy:latest@sha256:7f2e2149aa6a57ba382a140102fba44f5053f3e44389ccc18adcecf896054efb AS wsproxy
# Redis, the queues' broker for the background jobs (fastapi/test.sh: Celery's and RQ's workers; nextjs/test.sh: BullMQ)
FROM redis:8.10.3-alpine@sha256:21090af93f8324db2f0f0f4f38a7c60369d47d917e000c3423d89d2ae2883537 AS redis
# sqlc, which the Go suite runs to check the app's generated queries (integrations/go/test.sh)
FROM sqlc/sqlc:1.31.1@sha256:70f53171d27b2424e9358869975455a6e955a5aa8e58a998a270a6e34e525537 AS sqlc
# the Rails suite's Ruby (rails/test.sh builds rails/ruby.Dockerfile on it)
FROM ruby:4.0-slim@sha256:e41d40671d359ccc3431371e0af7c6430bd1b3886b47ac0667443525b7dcec1a AS ruby
# the Axum suite's Rust (axum/test.sh builds axum/rust.Dockerfile on it)
FROM rust:1.99-slim@sha256:b8e062b1c3a80183df83d9ba187cadd2b5ab84bc78d453dbfeb2fccd5f982247 AS rust
# the Phoenix suite's Elixir (phoenix/test.sh builds phoenix/elixir.Dockerfile on it)
FROM elixir:1.20-slim@sha256:6245171c91cf90808437f203f22856738d0095d310f4f9030219e53111823ff8 AS elixir
