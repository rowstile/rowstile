#!/bin/bash
# packaging/test.sh: the ways rowstile is installed, each checked on a clean machine (a container):
#   - npm: `rowstile` and `@rowstile/cli-linux-x64` from `npm pack`, installed where there is no Python at
#     all, on the lowest Node its engines state; the command runs on the Python that came with it (and fits the
#     size budget, 40 MB), and a command
#     stopped by a signal ends the launcher the same way; on Alpine (musl) with `@rowstile/cli-linux-x64-musl`
#   - PyPI: the `rowstile` wheel and sdist (the command and the Python SDK), installed with pip
#   - the command's image (packaging/docker/Dockerfile)
# Each compiles a policy, writes its migration and its generated names, with no database.
set -u
cd "$(dirname "$0")/.."
REPO=$(pwd)
OUT=packaging/out
rm -rf "$OUT" && mkdir -p "$OUT"
rc=0
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1"; rc=1; }

# the same few steps everywhere: $1 runs the command
SCRIPT='set -e
mkdir -p /tmp/app/db && cd /tmp/app
cp /repo/integrations/nextjs/db/policy.authz db/
printf "policy = \"db/policy.authz\"\n[clients]\nts = \"src/authz.gen.ts\"\n[migrations]\ntool = \"sql\"\ndir = \"db/migrations\"\n" > rowstile.toml
PGA --version
PGA check db/policy.authz
PGA migrate --name first >/dev/null
ls db/migrations | grep -q authz_first
PGA client ts db/policy.authz | grep -q "export const permissions"
echo done'

echo "-- npm"
# as the caller, not root: it writes into the checkout (packaging/npm/out, .cache), and a root-owned folder
# there can't be removed afterwards
as_me=(-u "$(id -u):$(id -g)" -e HOME=/tmp)
docker run --rm "${as_me[@]}" -v "$REPO:/repo" -w /repo node:24 bash -c \
  "node packaging/npm/build.mjs --platform linux-x64 --platform linux-x64-musl >/dev/null && cd $OUT && npm pack -s /repo/packaging/npm/out/rowstile /repo/packaging/npm/out/cli-linux-x64 /repo/packaging/npm/out/cli-linux-x64-musl >/dev/null" \
  || bad "the npm packages build"
size=$(stat -c %s "$OUT"/rowstile-cli-linux-x64-[0-9]*.tgz 2>/dev/null || echo 0)
[ "$size" -gt 0 ] && [ "$size" -lt 40000000 ] && ok "@rowstile/cli-linux-x64 is $((size / 1000000)) MB (under 40)" || bad "@rowstile/cli-linux-x64 is $size bytes"
# on the lowest Node the package's engines state (packaging/npm/rowstile/package.json); the others on Node 24
docker run --rm -v "$REPO:/repo" node:22.12.0-slim bash -c "
  ! command -v python3 >/dev/null && ! command -v python >/dev/null || { echo 'python is here'; exit 1; }
  echo node \$(node --version)
  mkdir -p /tmp/app && cd /tmp/app && npm init -y >/dev/null
  npm i --no-audit --no-fund --engine-strict /repo/$OUT/rowstile-cli-linux-x64-[0-9]*.tgz /repo/$OUT/rowstile-[0-9]*.tgz >/dev/null 2>&1 || exit 1
  ${SCRIPT//PGA/npx rowstile}" >"$OUT/npm.log" 2>&1 && grep -q "Python 3.13" "$OUT/npm.log" \
  && ok "npm: runs where there is no Python, on its own ($(grep -o 'Python [0-9.]*' "$OUT/npm.log")), on $(grep -o '^node v[0-9.]*' "$OUT/npm.log")" \
  || { cat "$OUT/npm.log"; bad "npm"; }
# a command that is stopped (SIGTERM, Ctrl-C, a hang-up, a kill) never looks finished to what started it
docker run --rm -v "$REPO:/repo" node:24-slim bash -c "
  mkdir -p /tmp/app && cd /tmp/app && npm init -y >/dev/null
  npm i --no-audit --no-fund /repo/$OUT/rowstile-cli-linux-x64-[0-9]*.tgz /repo/$OUT/rowstile-[0-9]*.tgz >/dev/null 2>&1 || exit 1
  node /repo/packaging/npm/signals_test.mjs node_modules/rowstile/bin/rowstile.js" >"$OUT/npm-signals.log" 2>&1 \
  && ok "npm: a command stopped by a signal ends the launcher by it ($(grep -c '^ok' "$OUT/npm-signals.log") signals)" \
  || { cat "$OUT/npm-signals.log"; bad "npm: a stopped command"; }
# Alpine: musl, where glibc's Python can't start; its own package, and still no Python on the machine
docker run --rm -v "$REPO:/repo" node:24-alpine sh -c "
  ! command -v python3 >/dev/null && ! command -v python >/dev/null || { echo 'python is here'; exit 1; }
  mkdir -p /tmp/app && cd /tmp/app && npm init -y >/dev/null
  npm i --no-audit --no-fund /repo/$OUT/rowstile-cli-linux-x64-musl-*.tgz /repo/$OUT/rowstile-[0-9]*.tgz >/dev/null 2>&1 || exit 1
  ${SCRIPT//PGA/npx rowstile}" >"$OUT/npm-musl.log" 2>&1 && grep -q "Python 3.13" "$OUT/npm-musl.log" \
  && ok "npm on Alpine (musl): runs on the Python of @rowstile/cli-linux-x64-musl" \
  || { cat "$OUT/npm-musl.log"; bad "npm on Alpine (musl)"; }
# the glibc package alone on Alpine (an npm that doesn't read libc, the wrong package copied): a sentence, not ENOENT
docker run --rm -v "$REPO:/repo" node:24-alpine sh -c "
  mkdir -p /tmp/app && cd /tmp/app && npm init -y >/dev/null
  npm i --no-audit --no-fund --force /repo/$OUT/rowstile-cli-linux-x64-[0-9]*.tgz /repo/$OUT/rowstile-[0-9]*.tgz >/dev/null 2>&1 || exit 1
  npx rowstile --version" >"$OUT/npm-musl-wrong.log" 2>&1; \
  grep -q "no Python to run on" "$OUT/npm-musl-wrong.log" && ! grep -q ENOENT "$OUT/npm-musl-wrong.log" \
  && ok "npm on Alpine with glibc's package only: says there is no Python to run on" \
  || { cat "$OUT/npm-musl-wrong.log"; bad "npm on Alpine with glibc's package only"; }

echo "-- PyPI"
docker run --rm -v "$REPO:/repo" python:3.13-slim bash -c "
  pip install -q build >/dev/null 2>&1 && mkdir -p /tmp/src/core && cp -r /repo/sdk /tmp/src/     && cp -r /repo/core/authzlib /repo/core/cli /tmp/src/core/     && mkdir -p /tmp/src/core/authzlib/__pycache__ && touch /tmp/src/core/authzlib/__pycache__/parse.cpython-313.pyc /tmp/src/core/authzlib/parse.py.orig /tmp/src/core/cli/notes.txt /tmp/src/core/cli/studio/notes.txt     && python -m build -o /tmp/dist /tmp/src/sdk/python >/dev/null && cp /tmp/dist/* /repo/$OUT/"   || bad "the wheel and sdist build"
ls "$OUT"/rowstile-*.whl "$OUT"/rowstile-*.tar.gz >/dev/null 2>&1 && ok "rowstile: a wheel and an sdist" || bad "no wheel or sdist"
for dist in whl tar.gz; do
  docker run --rm -v "$REPO:/repo" python:3.11-slim bash -c "
    pip install -q /repo/$OUT/rowstile-*.$dist >/dev/null 2>&1 || exit 1
    python -c 'import rowstile, rowstile.command' || exit 1
    python -c 'import authzlib' 2>/dev/null && { echo 'authzlib is importable at the top level'; exit 1; }
    ${SCRIPT//PGA/rowstile}" >"$OUT/pypi-$dist.log" 2>&1 \
    && ok "PyPI ($dist): pip install rowstile, then the command, on Python 3.11" || { cat "$OUT/pypi-$dist.log"; bad "PyPI ($dist)"; }
done
# the extras the stack pages tell people to install bring what the SDK's modules import: each in an environment
# of its own, with the newest of what it asks for (the conformance app pins and adds its own)
docker run --rm -v "$REPO:/repo" python:3.13-slim bash -c "
  set -e
  whl=\$(ls /repo/$OUT/rowstile-*.whl)
  try() { python -m venv /tmp/\$1 && /tmp/\$1/bin/pip install -q \"\$whl[\$2]\" >/dev/null 2>&1 && /tmp/\$1/bin/python -c \"\$3\" && echo \"\$2: ok\"; }
  try sync 'sqlalchemy,psycopg' 'import rowstile.sqlalchemy, rowstile.psycopg, rowstile.alembic'
  try pg 'asyncpg' 'import rowstile.asyncpg'
  try web 'fastapi,sqlalchemy,asyncpg' 'import rowstile.fastapi, rowstile.asyncpg; from sqlalchemy.ext.asyncio import create_async_engine'
  try plain 'fastapi' 'from rowstile.fastapi import Rowstile'" >"$OUT/pypi-extras.log" 2>&1 \
  && ok "PyPI: each extra of the stack pages, then the SDK's module for it, in a clean environment" \
  || { cat "$OUT/pypi-extras.log"; bad "PyPI: an extra doesn't bring what its module imports"; }

# every module of the command is in every package (a new one needs no list kept up to date)
python3 - "$OUT" <<'EOF' && ok "every module of core/cli, and Studio's page, is in the npm package and the wheel" || bad "a module is missing"
import glob, os, sys, tarfile, zipfile
want = {os.path.relpath(f, "core/cli").replace(os.sep, "/") for f in glob.glob("core/cli/*.py") + glob.glob("core/cli/studio/*")}
npm = {n.split("/command/cli/", 1)[1] for n in tarfile.open(glob.glob(sys.argv[1] + "/rowstile-[0-9]*.tgz")[0]).getnames() if "/command/cli/" in n}
whl = {n.split("/_command/cli/", 1)[1] for n in zipfile.ZipFile(glob.glob(sys.argv[1] + "/rowstile-*.whl")[0]).namelist() if "/_command/cli/" in n}
missing = {"npm": want - npm, "wheel": want - whl}
print(missing) if any(missing.values()) else None
sys.exit(1 if any(missing.values()) else 0)
EOF

# ... and nothing else of the tree they are built from: the build above put bytecode, a backup and notes beside them
python3 - "$OUT" <<'EOF' && ok "the wheel and the sdist hold the command's files, and no other file of the tree" || bad "the wheel or the sdist holds another file of the tree"
import glob, sys, tarfile, zipfile
want = {f[len("core/"):] for f in glob.glob("core/authzlib/*.py") + glob.glob("core/cli/*.py") + glob.glob("core/cli/studio/*")}
whl = zipfile.ZipFile(glob.glob(sys.argv[1] + "/rowstile-*.whl")[0]).namelist()
sdist = tarfile.open(glob.glob(sys.argv[1] + "/rowstile-*.tar.gz")[0]).getnames()
got = {kind: {n.split("/_command/", 1)[1] for n in names if "/_command/" in n} for kind, names in (("wheel", whl), ("sdist", sdist))}
wrong = {kind: (sorted(want - files), sorted(files - want)) for kind, files in got.items() if files != want}
print("(missing, not the command's):", wrong) if wrong else None
sys.exit(1 if wrong else 0)
EOF

# each package carries the licence it names
python3 - "$OUT" <<'EOF' && ok "the licence is in each npm package, the wheel and the sdist" || bad "a package without its licence"
import glob, sys, tarfile, zipfile
out, bare = sys.argv[1], []
for f in glob.glob(out + "/rowstile-*.tgz") + glob.glob(out + "/rowstile-*.tar.gz"):
    if not any(n.split("/", 1)[-1] == "LICENSE" for n in tarfile.open(f).getnames()):
        bare.append(f)
for f in glob.glob(out + "/rowstile-*.whl"):
    if not any(n.endswith(".dist-info/licenses/LICENSE") for n in zipfile.ZipFile(f).namelist()):
        bare.append(f)
print(bare) if bare else None
sys.exit(1 if bare else 0)
EOF
# ... and a platform package those of the libraries built into its Python (python-build-standalone's)
python3 - "$OUT" <<'EOF' && ok "each platform package holds the licences of the libraries built into its Python" || bad "a platform package without python/licenses"
import glob, sys, tarfile
packages = glob.glob(sys.argv[1] + "/rowstile-cli-*.tgz")
bare = [f for f in packages if not {"LICENSE.openssl-3.txt", "LICENSE.sqlite.txt", "LICENSE.zlib.txt", "LICENSE.cpython.txt"}
        <= {n.rsplit("/", 1)[-1] for n in tarfile.open(f).getnames() if "/python/licenses/" in n}]
print(bare) if bare else None
sys.exit(1 if bare or not packages else 0)
EOF

echo "-- the image"
docker build -q -t rowstile-cli:test -f packaging/docker/Dockerfile . >/dev/null || bad "the image builds"
docker run --rm -v "$REPO:/repo" --entrypoint bash rowstile-cli:test -c "git --version >/dev/null || exit 1
${SCRIPT//PGA/rowstile}" >"$OUT/image.log" 2>&1 \
  && ok "the image: rowstile, and git for reviews" || { cat "$OUT/image.log"; bad "the image"; }
# as the developer, not root (the README's line): what it writes into the project is theirs
docker run --rm -u 1000:1000 --tmpfs /work:uid=1000,gid=1000 -v "$REPO:/repo" --entrypoint bash rowstile-cli:test -c "
  mkdir db && cp /repo/integrations/nextjs/db/policy.authz db/ || exit 1
  printf 'policy = \"db/policy.authz\"\n[migrations]\ntool = \"sql\"\ndir = \"db/migrations\"\n' > rowstile.toml
  rowstile migrate --name first >/dev/null || exit 1
  [ \"\$(stat -c %u db/migrations/*authz_first.sql)\" = 1000 ]" >"$OUT/image-user.log" 2>&1 \
  && ok "the image as another user (-u): the migration is that user's" || { cat "$OUT/image-user.log"; bad "the image as another user"; }
exit $rc
