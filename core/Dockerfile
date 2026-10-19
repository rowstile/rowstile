# Postgres for developing and testing rowstile: the stock image, plus python3, git (rowstile review reads the
# base branch with it), the root certificates HTTPS is checked against (tests/upgrade.sh installs the release before
# this one from PyPI) and the rowstile command. rowstile needs nothing in the database but plain SQL and
# PL/pgSQL: the command compiles the policy and applies it as the tables' owner, with no superuser.
#   docker build -t rowstile:16 --build-arg PG_MAJOR=16 -f core/Dockerfile .
#   docker run -d --name pga -e POSTGRES_HOST_AUTH_METHOD=trust rowstile:16
#   docker exec -u postgres pga rowstile apply /path/to/policy.authz
# With --build-arg COVERAGE=1 it also measures what the suites run (ci.sh --coverage): coverage.py, which starts
# in every Python process when COVERAGE_PROCESS_START names its settings (run_tests.sh sets it), and is not even
# imported otherwise (a tenth of a second a process); and plpgsql_check (PGDG's package), whose profiler counts the
# statements of the PL/pgSQL functions the suites run (ci.sh --statements preloads it; tests/coverage_plpgsql.py).
# rowstile itself still needs no extension: it is made only for the moment the counts are read, then rolled back.
# Each Postgres by digest, a stage per major (Dependabot moves the digests, monthly: the newest patch release of
# each); PG_MAJOR picks one, and BuildKit builds only that one. Another version (a beta) has no stage here: ci.sh
# names its image for it (--build-context pg19beta4=docker-image://postgres:19beta4).
ARG PG_MAJOR=16
FROM postgres:16@sha256:ca0bd484cb98bf4b24eb1010e73fb3fcbd6714d240fbc1a10eea5b7dbecb641d AS pg16
FROM postgres:17@sha256:2d2b8998d31037bf721cfdf764d76ba74171b4fab3431b7f72c27c56ddbdf9e3 AS pg17
FROM postgres:18@sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336 AS pg18
FROM pg${PG_MAJOR}
ARG COVERAGE=
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 git ca-certificates \
      ${COVERAGE:+python3-coverage postgresql-$PG_MAJOR-plpgsql-check} \
 && rm -rf /var/lib/apt/lists/*
RUN if [ -n "$COVERAGE" ]; then \
      echo 'import os; os.environ.get("COVERAGE_PROCESS_START") and __import__("coverage").process_startup()' \
        > /usr/lib/python3/dist-packages/rowstile-coverage.pth; fi
# the suites run the mounted repository as root: no __pycache__ left in it that its owner can't remove (ci.sh
# gives the suites a cache in /tmp instead)
ENV PYTHONDONTWRITEBYTECODE=1
# psql, createdb and the others straight from this version's folder, not through Debian's wrapper in /usr/bin (a
# Perl script that picks the version on each call: 50 ms a call against 17, and the suites make thousands).
# PG_MAJOR is the stock image's
ENV PATH=/usr/lib/postgresql/$PG_MAJOR/bin:$PATH
COPY core/authzlib /opt/rowstile/authzlib
COPY core/cli /opt/rowstile/cli
RUN printf '#!/bin/sh\nexec python3 /opt/rowstile/cli/rowstile_cli.py "$@"\n' > /usr/local/bin/rowstile \
 && chmod 755 /usr/local/bin/rowstile
