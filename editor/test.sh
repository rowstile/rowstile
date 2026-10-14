#!/bin/bash
# test.sh: the editors' side, each in a container:
#   - the Tree-sitter grammar (tree-sitter-authz): src/ is what grammar.js generates, its corpus passes, and
#     every .authz file in the repository parses without an error, the queries included; and it reads each of
#     them, 200 random policies and core/tests/small.py's set up to size 4 (each written two ways), as
#     core/authzlib/parse.py does (core/tests/parse_agreement.py)
#   - the third evaluator (core/tests/third_compare.py), which reads policies through the grammar, against the
#     reference evaluator: every policy in the repository and the cases worked out by hand, in many worlds each
#   - the Zed extension builds (WebAssembly, as Zed builds it)
# Needs Docker and bash (Git Bash works on Windows).
#   editor/test.sh                  all of it (each push)
#   editor/test.sh --third "ARGS"   the third evaluator only, on the policies third_compare.py's ARGS choose
#                                   (nightly: --gen 250 --seed N, small.py's set: --small 5 --slice K/4)
#   editor/test.sh --agree "ARGS"   the grammar and the parser only, on small.py's set as parse_agreement.py's
#                                   ARGS choose it (nightly: all of it, --small 6 --slice K/4)
set -u
THIRD="" AGREE=""
[ "${1:-}" = "--third" ] && THIRD="${2:?--third ARGS}"
[ "${1:-}" = "--agree" ] && AGREE="${2:?--agree ARGS}"
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1
REPO=$(pwd -W 2>/dev/null || pwd)
rc=0
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1"; rc=1; }
# on Linux, as the caller: what the containers write in the checkout stays removable
as_me=(); [ "$(uname -s)" = Linux ] && as_me=(-u "$(id -u):$(id -g)" -e HOME=/tmp)

# the third evaluator against the reference evaluator: the policies third_compare.py writes (and lists, with the
# repository's), read by the grammar, then compared ($1: third_compare.py's choice of them and of the worlds)
third='python3 /repo/core/tests/third_compare.py --write /tmp/third $1 > /tmp/third.paths &&
    npx tree-sitter parse --xml --paths /tmp/third.paths > /tmp/third.xml 2>/dev/null &&
    python3 /repo/core/tests/third_compare.py /tmp/third.xml $2 -q > /tmp/third.log 2>&1 &&
    echo "ok    $(tail -n 1 /tmp/third.log)" || { cat /tmp/third.log; echo "FAIL  the third evaluator disagrees"; exit 1; }'

if [ -n "$THIRD" ]; then
  echo "-- the third evaluator: $THIRD"
  docker run --rm "${as_me[@]}" -v "$REPO:/repo" -w /repo/editor/tree-sitter-authz node:24-trixie bash -c '
    npm ci --no-audit --no-fund >/dev/null 2>&1 || { echo "FAIL  npm ci"; exit 1; }
    '"$third"'' third "$THIRD" "--worlds 20"
  exit $?
fi

if [ -n "$AGREE" ]; then
  echo "-- the grammar and the parser: $AGREE"
  # (many files: parsed in chunks, each an XML of its own, compared together; a chunk with a file the grammar
  # reads with an error exits 1, and the comparison says which, or that the parser refuses it too)
  docker run --rm "${as_me[@]}" -v "$REPO:/repo" -w /repo/editor/tree-sitter-authz node:24-trixie bash -c '
    npm ci --no-audit --no-fund >/dev/null 2>&1 || { echo "FAIL  npm ci"; exit 1; }
    python3 /repo/core/tests/parse_agreement.py --write /tmp/agree 0 $1 &&
      find /tmp/agree -name "*.authz" | sort > /tmp/paths && split -l 4000 /tmp/paths /tmp/chunk_ || exit 1
    for c in /tmp/chunk_*; do npx tree-sitter parse --xml --paths "$c" > "$c.xml" 2>/dev/null; [ -s "$c.xml" ] || { echo "FAIL  tree-sitter parse"; exit 1; }; done
    python3 /repo/core/tests/parse_agreement.py /tmp/chunk_*.xml > /tmp/agree.log 2>&1 &&
      echo "ok    $(tail -n 1 /tmp/agree.log)" || { tail -n 40 /tmp/agree.log; echo "FAIL  the grammar and the parser read a policy differently"; exit 1; }
  ' agree "$AGREE"
  exit $?
fi

echo "-- the grammar"
docker run --rm "${as_me[@]}" -v "$REPO:/repo" -w /repo/editor/tree-sitter-authz node:24-trixie bash -c '
  npm ci --no-audit --no-fund >/dev/null 2>&1 || { echo "FAIL  npm ci"; exit 1; }
  rm -rf /tmp/src && cp -r src /tmp/src && npx tree-sitter generate >/dev/null 2>&1 &&
    diff -r /tmp/src src >/dev/null && echo "ok    src/ is what grammar.js generates" ||
    { echo "FAIL  src/ is not what grammar.js generates: run npx tree-sitter generate"; exit 1; }
  npx tree-sitter test >/tmp/corpus.log 2>&1 && echo "ok    the corpus" || { cat /tmp/corpus.log; exit 1; }
  files=$(find /repo -name "*.authz" -not -path "*/node_modules/*" -not -path "*/.venv/*" | sort)
  npx tree-sitter parse -q $files 2>/dev/null && echo "ok    every policy in the repository parses ($(echo "$files" | wc -l) files)" ||
    { npx tree-sitter parse -q $files; echo "FAIL  a policy has a parse error"; exit 1; }
  # the grammar was written apart from core/authzlib/parse.py, which the compiler and the reference evaluator
  # share: each policy, 200 random ones and the small ones up to size 4, read alike by both (core/tests/parse_agreement.py)
  python3 /repo/core/tests/parse_agreement.py --write /tmp/gen 200 --small 4 &&
    { echo "$files"; ls /tmp/gen/*.authz; } > /tmp/paths && npx tree-sitter parse --xml --paths /tmp/paths > /tmp/all.xml 2>/dev/null &&
    python3 /repo/core/tests/parse_agreement.py /tmp/all.xml > /tmp/agree.log 2>&1 &&
    echo "ok    $(tail -n 1 /tmp/agree.log)" || { cat /tmp/agree.log; echo "FAIL  the grammar and the parser read a policy differently"; exit 1; }
  for q in queries/*.scm; do
    npx tree-sitter query -q "$q" $files >/dev/null 2>/tmp/query.log || { cat /tmp/query.log; echo "FAIL  $q"; exit 1; }
  done && echo "ok    the queries run on them"
  # the third evaluator, written apart from core/authzlib, reading the grammar'"'"'s trees: as the reference evaluator?
  '"$third"'
' third "" "--worlds 10" || rc=1

echo "-- the Zed extension"
docker run --rm "${as_me[@]}" -e CARGO_HOME=/tmp/cargo -v "$REPO:/repo" -w /repo/editor/zed rust:1 bash -c '
  cp -r /usr/local/cargo /tmp/cargo 2>/dev/null
  rustup target add wasm32-wasip2 >/dev/null 2>&1 &&
    cargo build -q --release --target wasm32-wasip2 --target-dir /tmp/target 2>&1 &&
    ls /tmp/target/wasm32-wasip2/release/rowstile_zed.wasm >/dev/null' \
  && ok "it builds for wasm32-wasip2" || bad "the Zed extension doesn't build"

exit $rc
