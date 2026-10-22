# The rowstile command as an image, for CI and for machines without Python: the rowstile package (the command
# and the Python SDK) built from this repository, and git (rowstile review reads the base branch with it).
#   docker build --build-arg VERSION=$(python3 packaging/version.py) -t rowstile-cli -f packaging/docker/Dockerfile .
#   docker run --rm -u "$(id -u):$(id -g)" -v "$PWD:/work" -e DATABASE_URL rowstile-cli migrate
# (-u: what it writes into the project, a migration, the lock file, is then the caller's, not root's)
FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f AS build
COPY core/authzlib /src/core/authzlib
COPY core/cli /src/core/cli
COPY sdk/python /src/sdk/python
# the version the image's label gives (release.yml passes it): the package's own, or the build stops
ARG VERSION
RUN v=$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' /src/core/authzlib/__init__.py) \
 && if [ -z "$v" ] || [ "$VERSION" != "$v" ]; then echo "the image is labelled with the package's version: --build-arg VERSION=$v (it is '$VERSION')" >&2; exit 1; fi
RUN pip wheel --no-cache-dir --no-deps -w /wheels /src/sdk/python

FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f
# what the image's page shows: `source` ties it to the repository, whose README the registry then shows
ARG VERSION
LABEL org.opencontainers.image.title="rowstile" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.description="Access rules for Postgres: the rowstile command (policies compiled to row-level security, shipped as migrations)" \
      org.opencontainers.image.source="https://github.com/rowstile/rowstile" \
      org.opencontainers.image.url="https://rowstile.dev" \
      org.opencontainers.image.documentation="https://rowstile.dev/installing" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels \
 && git config --system --add safe.directory '*'
WORKDIR /work
ENTRYPOINT ["rowstile"]
CMD ["--help"]
