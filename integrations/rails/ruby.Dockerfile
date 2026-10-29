# The Rails suite's Ruby side (test.sh builds it, and runs the app, the checks, Steep and the gem's build in it):
# the official Ruby image pinned in ../images/Dockerfile (by digest, which Dependabot moves there), with what its
# gems and the checks need. A compiler for
# the gems with C code (rbs, which Steep reads signatures with); pg_dump and psql of PostgreSQL 18, from PGDG, for
# db/structure.sql (Rails dumps it with pg_dump, which refuses a server newer than itself, and whose newer versions
# write more settings at the top: one version for every server the suite runs on, so the dump is the same on each);
# python3 for the rowstile command (check 14 runs rowstile migrate and rowstile client from the tests).
#   docker build -t rowstile-rails --build-arg RUBY_IMAGE=<ruby image> -f integrations/rails/ruby.Dockerfile integrations/rails
ARG RUBY_IMAGE
FROM ${RUBY_IMAGE}
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libyaml-dev python3 postgresql-common ca-certificates \
 && /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y >/dev/null \
 && apt-get install -y --no-install-recommends postgresql-client-18 \
 && rm -rf /var/lib/apt/lists/*
ENV PATH=/usr/lib/postgresql/18/bin:$PATH
