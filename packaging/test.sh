#!/bin/bash
# packaging/test.sh: the ways rowstile is installed, each checked on a clean machine (a container; each image is
# pinned in packaging/machines/Dockerfile):
#   - npm: `rowstile` and the seven platform packages from `npm pack`, each under the size budget (20 MB). On
#     Linux x64, installed where there is no Python at all, on the lowest Node its engines state (the others on
#     Node 24): the command runs on the Python that came with it, a
#     command stopped by a signal ends the launcher the same way, and on Alpine (musl) it runs on
#     `@rowstile/cli-linux-x64-musl`. On Linux arm64, glibc and musl alike, the same, where this machine runs
#     arm64 containers (emulated, as CI sets up: required there, skipped elsewhere). Without its platform
#     package (optional dependencies off), on the Python found on PATH; with ROWSTILE_PYTHON, on that one, a 3.11
#     or later; a bundled Python it can't make executable is said to be so. The macOS and Windows packages can't be
#     started on Linux: packaging/npm/platforms.py reads every package instead (its Python is built for the
#     package's system and CPU, every library a binary loads is there, and every module the command imports)
#   - PyPI: the `rowstile` wheel and sdist (the command and the Python SDK), installed with pip
#   - the command's image (packaging/docker/Dockerfile), on each platform the release publishes it for, and its version label
# Each compiles a policy, writes its migration and its generated names, with no database.
set -u
cd "$(dirname "$0")/.."
REPO=$(pwd)
OUT=packaging/out
rm -rf "$OUT" && mkdir -p "$OUT"
rc=0
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1"; rc=1; }
skip() { echo "skip  $1"; }

# each clean machine's image, by its stage's name
machine() { sed -n "s/^FROM \([^ ]*\) AS $1\$/\1/p" packaging/machines/Dockerfile; }
NODE=$(machine node) NODE_FLOOR=$(machine node-floor) NODE_SLIM=$(machine node-slim) NODE_ALPINE=$(machine node-alpine)
PYTHON=$(machine python) PYTHON_311=$(machine python-3.11)
for image in "$NODE" "$NODE_FLOOR" "$NODE_SLIM" "$NODE_ALPINE" "$PYTHON" "$PYTHON_311"; do
  [ -n "$image" ] || { bad "packaging/machines/Dockerfile names each machine"; exit 1; }
done

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
# from a copy of what the build reads, with what a developer's tree may hold beside the command's files: bytecode,
# an editor's backup, notes (a check below asks that none of it goes in)
docker run --rm "${as_me[@]}" -v "$REPO:/repo" -w /repo "$NODE" bash -c "set -e
  mkdir -p /tmp/src/core /tmp/src/sdk/python /tmp/src/packaging/npm packaging/npm/.cache
  cp -r core/authzlib core/cli /tmp/src/core/ && cp LICENSE /tmp/src/ && cp sdk/python/command-files.txt /tmp/src/sdk/python/
  cp -r packaging/npm/build.mjs packaging/npm/rowstile packaging/npm/python-licenses /tmp/src/packaging/npm/
  ln -s /repo/packaging/npm/.cache /tmp/src/packaging/npm/.cache
  mkdir -p /tmp/src/core/authzlib/__pycache__ && touch /tmp/src/core/authzlib/__pycache__/parse.cpython-313.pyc \
    /tmp/src/core/authzlib/parse.py.orig /tmp/src/core/cli/notes.txt /tmp/src/core/cli/studio/notes.txt
  node /tmp/src/packaging/npm/build.mjs --all >/dev/null
  cd $OUT && npm pack -s /tmp/src/packaging/npm/out/rowstile /tmp/src/packaging/npm/out/cli-* >/dev/null" \
  || bad "the npm packages build"
big=()
for f in "$OUT"/rowstile-cli-*.tgz; do
  [ -e "$f" ] && [ "$(stat -c %s "$f")" -lt 20000000 ] || big+=("$(basename "$f")")
done
n=$(ls "$OUT"/rowstile-cli-*.tgz 2>/dev/null | wc -l)
[ "$n" = 7 ] && [ ${#big[@]} = 0 ] && ok "the seven platform packages, each under 20 MB (@rowstile/cli-linux-x64: $(($(stat -c %s "$OUT"/rowstile-cli-linux-x64-[0-9]*.tgz) / 1000000)) MB)" \
  || bad "$n platform packages; over 20 MB: ${big[*]}"
# what Linux can say of each, those it can't start included: on the Python they bring, which reads its library
docker run --rm "${as_me[@]}" -v "$REPO:/repo" -w /repo "$PYTHON" python3 packaging/npm/platforms.py $OUT/rowstile-cli-*.tgz \
  >"$OUT/npm-platforms.log" 2>&1 \
  && ok "each platform package: its Python is built for its system and CPU, and holds every library it loads and every module the command imports" \
  || { cat "$OUT/npm-platforms.log"; bad "a platform package as read"; }
# on the lowest Node the package's engines state (packaging/npm/rowstile/package.json); the others on Node 24
docker run --rm -v "$REPO:/repo" "$NODE_FLOOR" bash -c "
  ! command -v python3 >/dev/null && ! command -v python >/dev/null || { echo 'python is here'; exit 1; }
  echo node \$(node --version)
  mkdir -p /tmp/app && cd /tmp/app && npm init -y >/dev/null
  npm i --no-audit --no-fund --engine-strict /repo/$OUT/rowstile-cli-linux-x64-[0-9]*.tgz /repo/$OUT/rowstile-[0-9]*.tgz >/dev/null 2>&1 || exit 1
  ${SCRIPT//PGA/npx rowstile}" >"$OUT/npm.log" 2>&1 && grep -q "Python 3.13" "$OUT/npm.log" \
  && ok "npm: runs where there is no Python, on its own ($(grep -o 'Python [0-9.]*' "$OUT/npm.log")), on $(grep -o '^node v[0-9.]*' "$OUT/npm.log")" \
  || { cat "$OUT/npm.log"; bad "npm"; }
# a command that is stopped (SIGTERM, Ctrl-C, a hang-up, a kill) never looks finished to what started it
docker run --rm -v "$REPO:/repo" "$NODE_SLIM" bash -c "
  mkdir -p /tmp/app && cd /tmp/app && npm init -y >/dev/null
  npm i --no-audit --no-fund /repo/$OUT/rowstile-cli-linux-x64-[0-9]*.tgz /repo/$OUT/rowstile-[0-9]*.tgz >/dev/null 2>&1 || exit 1
  node /repo/packaging/npm/signals_test.mjs node_modules/rowstile/bin/rowstile.js" >"$OUT/npm-signals.log" 2>&1 \
  && ok "npm: a command stopped by a signal ends the launcher by it ($(grep -c '^ok' "$OUT/npm-signals.log") signals)" \
  || { cat "$OUT/npm-signals.log"; bad "npm: a stopped command"; }
# Alpine: musl, where glibc's Python can't start; its own package, and still no Python on the machine
docker run --rm -v "$REPO:/repo" "$NODE_ALPINE" sh -c "
  ! command -v python3 >/dev/null && ! command -v python >/dev/null || { echo 'python is here'; exit 1; }
  mkdir -p /tmp/app && cd /tmp/app && npm init -y >/dev/null
  npm i --no-audit --no-fund /repo/$OUT/rowstile-cli-linux-x64-musl-*.tgz /repo/$OUT/rowstile-[0-9]*.tgz >/dev/null 2>&1 || exit 1
  ${SCRIPT//PGA/npx rowstile}" >"$OUT/npm-musl.log" 2>&1 && grep -q "Python 3.13" "$OUT/npm-musl.log" \
  && ok "npm on Alpine (musl): runs on the Python of @rowstile/cli-linux-x64-musl" \
  || { cat "$OUT/npm-musl.log"; bad "npm on Alpine (musl)"; }
# the glibc package alone on Alpine (an npm that doesn't read libc, the wrong package copied): a sentence, not ENOENT
docker run --rm -v "$REPO:/repo" "$NODE_ALPINE" sh -c "
  mkdir -p /tmp/app && cd /tmp/app && npm init -y >/dev/null
  npm i --no-audit --no-fund --force /repo/$OUT/rowstile-cli-linux-x64-[0-9]*.tgz /repo/$OUT/rowstile-[0-9]*.tgz >/dev/null 2>&1 || exit 1
  npx rowstile --version" >"$OUT/npm-musl-wrong.log" 2>&1; \
  grep -q "no Python to run on" "$OUT/npm-musl-wrong.log" && ! grep -q ENOENT "$OUT/npm-musl-wrong.log" \
  && ok "npm on Alpine with glibc's package only: says there is no Python to run on" \
  || { cat "$OUT/npm-musl-wrong.log"; bad "npm on Alpine with glibc's package only"; }
# Linux arm64, glibc and musl: the same steps, on an arm64 machine or one that emulates it (CI registers QEMU's
# emulator first: there it is required)
if [ "$(uname -m)" = aarch64 ] || [ -e /proc/sys/fs/binfmt_misc/qemu-aarch64 ]; then
  for libc in glibc musl; do
    if [ $libc = glibc ]; then image=$NODE_SLIM pkg=linux-arm64 tgz="rowstile-cli-linux-arm64-[0-9]*.tgz"
    else image=$NODE_ALPINE pkg=linux-arm64-musl tgz="rowstile-cli-linux-arm64-musl-*.tgz"; fi
    docker run --rm --platform linux/arm64 -v "$REPO:/repo" "$image" sh -c "
      [ \"\$(uname -m)\" = aarch64 ] || { echo \"not arm64: \$(uname -m)\"; exit 1; }
      ! command -v python3 >/dev/null && ! command -v python >/dev/null || { echo 'python is here'; exit 1; }
      mkdir -p /tmp/app && cd /tmp/app && npm init -y >/dev/null
      npm i --no-audit --no-fund /repo/$OUT/$tgz /repo/$OUT/rowstile-[0-9]*.tgz >/dev/null 2>&1 || exit 1
      ${SCRIPT//PGA/npx rowstile}" >"$OUT/npm-$pkg.log" 2>&1 && grep -q "Python 3.13" "$OUT/npm-$pkg.log" \
      && ok "npm on Linux arm64 ($libc): runs on the Python of @rowstile/cli-$pkg" \
      || { cat "$OUT/npm-$pkg.log"; bad "npm on Linux arm64 ($libc)"; }
  done
elif [ "${GITHUB_ACTIONS:-}" = true ]; then
  bad "npm on Linux arm64: this runner can't run arm64 containers (the workflow sets up QEMU's emulator first)"
else
  skip "npm on Linux arm64: this machine runs no arm64 containers (no QEMU emulator registered); CI runs it"
fi
# no platform package (optional dependencies off, a platform with none): the Python on PATH, which the message
# for "no Python to run on" sends the user to
docker run --rm -v "$REPO:/repo" "$NODE" bash -c "
  echo \"on PATH: \$(python3 --version)\"
  mkdir -p /tmp/app && cd /tmp/app && npm init -y >/dev/null
  npm i --no-audit --no-fund --omit=optional /repo/$OUT/rowstile-[0-9]*.tgz >/dev/null 2>&1 || exit 1
  [ ! -e node_modules/@rowstile ] || { echo 'a platform package is installed'; exit 1; }
  ${SCRIPT//PGA/npx rowstile}" >"$OUT/npm-path.log" 2>&1 \
  && grep -qF "(Python $(sed -n 's/^on PATH: Python //p' "$OUT/npm-path.log"))" "$OUT/npm-path.log" \
  && ok "npm without its platform package: runs on the Python on PATH ($(sed -n 's/^on PATH: //p' "$OUT/npm-path.log"))" \
  || { cat "$OUT/npm-path.log"; bad "npm without its platform package"; }
# ROWSTILE_PYTHON: the Python to run on instead, asked its version first: one older than 3.11, or no Python, is
# refused with a sentence
docker run --rm -v "$REPO:/repo" "$NODE" bash -c "
  echo \"on PATH: \$(python3 --version)\"
  mkdir -p /tmp/app && cd /tmp/app && npm init -y >/dev/null
  npm i --no-audit --no-fund /repo/$OUT/rowstile-cli-linux-x64-[0-9]*.tgz /repo/$OUT/rowstile-[0-9]*.tgz >/dev/null 2>&1 || exit 1
  ROWSTILE_PYTHON=\$(command -v python3) npx rowstile --version || exit 1
  printf '#!/bin/sh\necho 3.10.12\n' > /tmp/python3.10 && chmod +x /tmp/python3.10
  for p in /tmp/python3.10 /bin/echo /nowhere/python; do ROWSTILE_PYTHON=\$p npx rowstile --version; echo \"exit \$?\"; done" \
  >"$OUT/npm-chosen.log" 2>&1 \
  && grep -qF "(Python $(sed -n 's/^on PATH: Python //p' "$OUT/npm-chosen.log"))" "$OUT/npm-chosen.log" \
  && grep -qF "rowstile: ROWSTILE_PYTHON is /tmp/python3.10, which is Python 3.10.12: name a Python 3.11 or later" "$OUT/npm-chosen.log" \
  && grep -qF "rowstile: ROWSTILE_PYTHON is /bin/echo, which isn't a Python: name" "$OUT/npm-chosen.log" \
  && grep -qF "rowstile: ROWSTILE_PYTHON is /nowhere/python, which can't be run (spawnSync /nowhere/python ENOENT): name" "$OUT/npm-chosen.log" \
  && [ "$(grep -c '^exit 1$' "$OUT/npm-chosen.log")" = 3 ] \
  && ok "npm: ROWSTILE_PYTHON runs it on that Python, and refuses one older than 3.11, or none, saying why" \
  || { cat "$OUT/npm-chosen.log"; bad "npm with ROWSTILE_PYTHON"; }
# the bundled Python not executable, and this user can't change that (a node_modules another user installed): said
# as such, not as a package that isn't installed
docker run --rm -v "$REPO:/repo" "$NODE_SLIM" bash -c "
  mkdir -p /tmp/app && cd /tmp/app && npm init -y >/dev/null
  npm i --no-audit --no-fund /repo/$OUT/rowstile-cli-linux-x64-[0-9]*.tgz /repo/$OUT/rowstile-[0-9]*.tgz >/dev/null 2>&1 || exit 1
  chmod -x node_modules/@rowstile/cli-linux-x64/python/bin/python3.*
  su node -s /bin/sh -c 'node /tmp/app/node_modules/rowstile/bin/rowstile.js --version'" >"$OUT/npm-mode.log" 2>&1; \
  grep -q "^rowstile: no Python to run on. The Python of @rowstile/cli-linux-x64 (.*python3\.[0-9]*) isn't executable, and can't be made so (EPERM" "$OUT/npm-mode.log" \
  && ! grep -q "isn't installed" "$OUT/npm-mode.log" \
  && ok "npm: a bundled Python this user can't make executable is said to be so" \
  || { cat "$OUT/npm-mode.log"; bad "npm with a bundled Python that isn't executable"; }

echo "-- PyPI"
docker run --rm -v "$REPO:/repo" "$PYTHON" bash -c "
  pip install -q build >/dev/null 2>&1 && mkdir -p /tmp/src/core && cp -r /repo/sdk /tmp/src/     && cp -r /repo/core/authzlib /repo/core/cli /tmp/src/core/     && mkdir -p /tmp/src/core/authzlib/__pycache__ && touch /tmp/src/core/authzlib/__pycache__/parse.cpython-313.pyc /tmp/src/core/authzlib/parse.py.orig /tmp/src/core/cli/notes.txt /tmp/src/core/cli/studio/notes.txt     && python -m build -o /tmp/dist /tmp/src/sdk/python >/dev/null && cp /tmp/dist/* /repo/$OUT/"   || bad "the wheel and sdist build"
ls "$OUT"/rowstile-*.whl "$OUT"/rowstile-*.tar.gz >/dev/null 2>&1 && ok "rowstile: a wheel and an sdist" || bad "no wheel or sdist"
for dist in whl tar.gz; do
  docker run --rm -v "$REPO:/repo" "$PYTHON_311" bash -c "
    pip install -q /repo/$OUT/rowstile-*.$dist >/dev/null 2>&1 || exit 1
    python -c 'import rowstile, rowstile.command' || exit 1
    python -c 'import authzlib' 2>/dev/null && { echo 'authzlib is importable at the top level'; exit 1; }
    ${SCRIPT//PGA/rowstile}" >"$OUT/pypi-$dist.log" 2>&1 \
    && ok "PyPI ($dist): pip install rowstile, then the command, on Python 3.11" || { cat "$OUT/pypi-$dist.log"; bad "PyPI ($dist)"; }
done
# the extras the stack pages tell people to install bring what the SDK's modules import: each in an environment
# of its own, with the newest of what it asks for (the conformance app pins and adds its own)
docker run --rm -v "$REPO:/repo" "$PYTHON" bash -c "
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

# ... and nothing else of the tree it is built from: the npm build above put bytecode, a backup and notes beside them
python3 - "$OUT" <<'EOF' && ok "the npm package holds the command's files, and no other file of the tree" || bad "the npm package holds another file of the tree"
import glob, sys, tarfile
want = {f[len("core/"):] for f in glob.glob("core/authzlib/*.py") + glob.glob("core/cli/*.py") + glob.glob("core/cli/studio/*")}
names = tarfile.open(glob.glob(sys.argv[1] + "/rowstile-[0-9]*.tgz")[0]).getnames()
got = {n.split("/command/", 1)[1] for n in names if "/command/" in n}
print("missing:", sorted(want - got), "not the command's:", sorted(got - want)) if got != want else None
sys.exit(1 if got != want else 0)
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
# ... and a platform package those of the libraries built into its Python (python-build-standalone's): each text of
# packaging/npm/python-licenses, and no other
python3 - "$OUT" <<'EOF' && ok "each platform package holds the licences of the libraries built into its Python" || bad "a platform package without python/licenses as it is"
import glob, os, sys, tarfile
want = sorted(os.listdir("packaging/npm/python-licenses"))
packages = glob.glob(sys.argv[1] + "/rowstile-cli-*.tgz")
wrong = {f: got for f in packages
         if (got := sorted(n.rsplit("/", 1)[-1] for n in tarfile.open(f).getnames() if "/python/licenses/" in n)) != want}
print(f"python-licenses: {want}", wrong) if wrong else None
sys.exit(1 if wrong or not packages else 0)
EOF
# ... and none of what its Python never loads: libpython (the binary is linked statically), python3.13-config, and
# _dbm (Berkeley DB, which the command never imports)
python3 - "$OUT" <<'EOF' && ok "no platform package holds libpython, python3.13-config or _dbm" || bad "a platform package holds what its Python never loads"
import glob, re, sys, tarfile
packages = glob.glob(sys.argv[1] + "/rowstile-cli-*.tgz")
extra = [n for f in packages for n in tarfile.open(f).getnames()
         if re.search(r"/(libpython3[^/]*|python3[^/]*-config|_dbm\.[^/]*)$", n)]
print(extra) if extra else None
sys.exit(1 if extra or not packages else 0)
EOF

echo "-- the image"
# on each platform the release publishes it for (release.yml's `platforms`): CI names them in
# ROWSTILE_IMAGE_PLATFORMS and runs arm64 under QEMU; elsewhere on the machine's own
version=$(python3 packaging/version.py)
IFS=, read -ra platforms <<<"${ROWSTILE_IMAGE_PLATFORMS:-linux/$(docker version -f '{{.Server.Arch}}')}"
for platform in "${platforms[@]}"; do
  arch=${platform#linux/}
  image=rowstile-cli:test-$arch
  case $arch in amd64) machine=x86_64 ;; arm64) machine=aarch64 ;; *) machine=$arch ;; esac
  docker build -q --platform "$platform" --build-arg VERSION="$version" -t "$image" -f packaging/docker/Dockerfile . \
    >/dev/null || bad "the image builds ($platform)"
  label=$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.version"}}' "$image" 2>&1)
  [ "$label" = "$version" ] && ok "the image ($platform) is labelled with its version, $version" \
    || bad "the image ($platform): its version label is '$label', not $version"
  docker run --rm --platform "$platform" -v "$REPO:/repo" --entrypoint bash "$image" -c "git --version >/dev/null || exit 1
echo \"machine \$(uname -m)\"
${SCRIPT//PGA/rowstile}" >"$OUT/image-$arch.log" 2>&1 && grep -qx "machine $machine" "$OUT/image-$arch.log" \
    && ok "the image ($platform): rowstile on $machine, and git for reviews" \
    || { cat "$OUT/image-$arch.log"; bad "the image ($platform)"; }
  # as the developer, not root (the README's line): what it writes into the project is theirs
  docker run --rm --platform "$platform" -u 1000:1000 --tmpfs /work:uid=1000,gid=1000 -v "$REPO:/repo" --entrypoint bash "$image" -c "
    mkdir db && cp /repo/integrations/nextjs/db/policy.authz db/ || exit 1
    printf 'policy = \"db/policy.authz\"\n[migrations]\ntool = \"sql\"\ndir = \"db/migrations\"\n' > rowstile.toml
    rowstile migrate --name first >/dev/null || exit 1
    [ \"\$(stat -c %u db/migrations/*authz_first.sql)\" = 1000 ]" >"$OUT/image-user-$arch.log" 2>&1 \
    && ok "the image ($platform) as another user (-u): the migration is that user's" \
    || { cat "$OUT/image-user-$arch.log"; bad "the image ($platform) as another user"; }
done
# a version that isn't the package's stops the build: the label never says another
! docker build --progress=plain --build-arg VERSION=0.0.0 -f packaging/docker/Dockerfile . >"$OUT/image-version.log" 2>&1 \
  && grep -qF "the image is labelled with the package's version: --build-arg VERSION=$version (it is '0.0.0')" "$OUT/image-version.log" \
  && ok "the image: a build given another version than the package's stops, and says which" \
  || { cat "$OUT/image-version.log"; bad "the image built with another version than the package's"; }
exit $rc
