# The services the conformance suites start beside Postgres (pooler.sh: PgBouncer), a stage each, pinned by digest
# as the other images are (Dependabot moves the digests). Never built: the scripts read each stage's image by its
# name.
FROM edoburu/pgbouncer:v1.26.1-p0@sha256:488422e38cff912895d0d65d8963fcd306e6ac589a724398b6eb8e294e94d624 AS pgbouncer
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
# the Laravel suite's PHP and Composer (laravel/test.sh builds laravel/php.Dockerfile on them)
FROM php:8.4-cli-alpine@sha256:d8784155c4d37986be9ddd7a8950df7e78998cc48e35472cd69e2b9371424a65 AS php
FROM composer:2.9@sha256:b09bccd91a78fe8a9ab4b33d707b862e8fe54fec17782e32683ad2a69c46867d AS composer
# Electric, the sync engine (electric/test.sh, a preview), and nginx, the shared cache it puts in front of the app
FROM electricsql/electric:1.8.1@sha256:efb6fa43859d67cb8c73439e0c8bc0f7a3daa467500fb06f2a924bcb2070c139 AS electric
FROM nginx:1.31.8-alpine-slim@sha256:f45171d36c76a8b2f5ef97108a3a8a2294248a6578a0a180edc2d78f7d2edc26 AS nginx
