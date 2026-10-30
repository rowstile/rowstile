# The Phoenix suite's Elixir side (test.sh builds it, and runs the SDK's checks, the app and its tests in it): the
# official Elixir image pinned in ../images/Dockerfile (by digest, which Dependabot moves there), with python3 for
# the rowstile command (checks 9 and 14 run rowstile client and rowstile migrate from the tests) and the root
# certificates (Hex fetches the packages over HTTPS).
#   docker build -t rowstile-phoenix --build-arg ELIXIR_IMAGE=<elixir image> -f integrations/phoenix/elixir.Dockerfile integrations/phoenix
ARG ELIXIR_IMAGE
FROM ${ELIXIR_IMAGE}
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*
