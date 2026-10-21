#!/bin/bash
# test.sh: the editors' side, each in a container:
#   - the Tree-sitter grammar (tree-sitter-authz): src/ is what grammar.js generates, its corpus passes, and
#     every .authz file in the repository parses without an error, the queries included; and it reads each of
#     them, 200 random policies and core/tests/small.py's set up to size 4 (each written two ways), as
#     core/authzlib/parse.py does (core/tests/parse_agreement.py)
#   - the VS Code extension packages as the README says, with the licence and only full addresses on its
#     Marketplace page, and extension.js passes extension_test.js
#   - Neovim highlights a policy with the README's steps
#   - the Zed extension builds (WebAssembly, as Zed builds it)
# Needs Docker and bash.
#   editor/test.sh                  all of it (each push)
#   editor/test.sh --agree "ARGS"   the grammar and the parser only, on small.py's set as parse_agreement.py's
#                                   ARGS choose it (nightly: all of it, --small 6 --slice K/4)
set -u
AGREE=""
[ "${1:-}" = "--agree" ] && AGREE="${2:?--agree ARGS}"
cd "$(dirname "$0")/.."
REPO=$(pwd)
rc=0
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1"; rc=1; }
# as the caller: what the containers write in the checkout stays removable
as_me=(-u "$(id -u):$(id -g)" -e HOME=/tmp)

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
' || rc=1

echo "-- the VS Code extension"
# a copy of the extension: what the README says to run writes node_modules and the .vsix where it runs
docker run --rm "${as_me[@]}" -v "$REPO:/repo:ro" node:24-trixie bash -c '
  mkdir -p /tmp/ext/editor && cd /tmp/ext || exit 1
  tar -C /repo/editor --exclude=node_modules --exclude=tree-sitter-authz --exclude=zed --exclude="*.vsix" -c . | tar -x -C editor
  # the README line that builds it from this repository
  steps=$(grep -m 1 "^    cd editor && " /repo/editor/README.md | sed "s/#.*//")
  [ -n "$steps" ] && bash -c "$steps" > /tmp/package.log 2>&1 && ls editor/rowstile-*.vsix > /dev/null 2>&1 &&
    echo "ok    it packages as the README says" || { cat /tmp/package.log; echo "FAIL  it does not package as the README says"; exit 1; }
  # the .vsix carries the licence, and its README is the extension page on the Marketplace and Open VSX: a
  # relative link there leads nowhere (vsce writes ../docs/x.md as github.com/.../blob/HEAD/../docs/x.md)
  python3 - editor/rowstile-*.vsix <<"EOF" || exit 1
import re, sys, zipfile
vsix = zipfile.ZipFile(sys.argv[1])
fail = False
if vsix.read("extension/LICENSE.txt") != open("/repo/LICENSE", "rb").read():
    print("FAIL  the .vsix has the repository LICENSE")
    fail = True
links = re.findall(r"\]\(([^)\s]+)\)", vsix.read("extension/readme.md").decode())
wrong = [link for link in links if not link.startswith("https://") or "/../" in link or "/HEAD/" in link]
if wrong or not links:
    print("FAIL  every link on its Marketplace page is a full address: " + ", ".join(wrong))
    fail = True
if fail:
    sys.exit(1)
print(f"ok    the .vsix has the licence, and each link on its page is a full address ({len(links)})")
EOF
  cd editor && node extension_test.js
' || rc=1

echo "-- Neovim"
# the README steps (build the grammar, put it and its queries in the config folder, its init.lua) on the oldest
# Neovim it names, and a policy is highlighted
docker run --rm "${as_me[@]}" -v "$REPO:/repo:ro" node:24-trixie bash -c '
  case $(uname -m) in
    x86_64) arch=x86_64 sum=a74740047e73b2b380d63a474282814063d10650cd6cc95efa16d1713c7e616c ;;
    *) arch=arm64 sum=684e4262d2296e469cb43f0d05edbbb52b960b7f117bed6b22936fc768993cd9 ;;
  esac
  curl -sfL -o /tmp/nvim.tar.gz "https://github.com/neovim/neovim/releases/download/v0.11.4/nvim-linux-$arch.tar.gz" &&
    echo "$sum  /tmp/nvim.tar.gz" | sha256sum -c --quiet && tar -xzf /tmp/nvim.tar.gz -C /tmp ||
    { echo "FAIL  Neovim 0.11.4 could not be downloaded"; exit 1; }
  export PATH="/tmp/nvim-linux-$arch/bin:$PATH" HOME=/tmp/home
  mkdir -p /tmp/ts && tar -C /repo/editor/tree-sitter-authz --exclude=node_modules -c . | tar -x -C /tmp/ts && cd /tmp/ts || exit 1
  python3 - /repo/editor/README.md <<"EOF" || { echo "FAIL  the README gives no steps for Neovim 0.11"; exit 1; }
import os, re, sys
text = open(sys.argv[1]).read()
part = text[text.index("\nNeovim 0.11") : text.index("\nHelix (")]
open("/tmp/steps.sh", "w").write("\n".join(line[4:] for line in part.split("\n") if line.startswith("    ")) + "\n")
os.makedirs(os.path.expanduser("~/.config/nvim"), exist_ok=True)
open(os.path.expanduser("~/.config/nvim/init.lua"), "w").write(re.search(r"```lua\n(.*?)```", part, re.S).group(1))
EOF
  bash -e /tmp/steps.sh > /tmp/steps.log 2>&1 || { cat /tmp/steps.log; echo "FAIL  the README steps for Neovim"; exit 1; }
  cat > /tmp/check.lua <<"EOF"
local buf = vim.api.nvim_get_current_buf()
local active = vim.treesitter.highlighter.active[buf] ~= nil
local caps = {}
if active then
  local tree = vim.treesitter.get_parser(buf):parse()[1]
  local query = vim.treesitter.query.get("authz", "highlights")
  for id in query:iter_captures(tree:root(), buf, 0, -1) do caps[query.captures[id]] = true end
end
local names = vim.tbl_keys(caps)
table.sort(names)
io.stdout:write("filetype=" .. vim.bo.filetype .. " highlighted=" .. tostring(active) .. " captures=" .. table.concat(names, ",") .. "\n")
EOF
  # (no language server here: Neovim says so on stderr)
  out=$(nvim --headless /repo/core/example/docs.authz -c "luafile /tmp/check.lua" -c "qa!" 2>/dev/null)
  case "$out" in
    *"filetype=authz highlighted=true"*function*keyword*type*) echo "ok    Neovim 0.11 highlights a policy as the README sets it up" ;;
    *) echo "FAIL  Neovim does not highlight a policy as the README sets it up: $out"; exit 1 ;;
  esac
' || rc=1

echo "-- the Zed extension"
docker run --rm "${as_me[@]}" -e CARGO_HOME=/tmp/cargo -v "$REPO:/repo" -w /repo/editor/zed rust:1 bash -c '
  cp -r /usr/local/cargo /tmp/cargo 2>/dev/null
  rustup target add wasm32-wasip2 >/dev/null 2>&1 &&
    cargo build -q --release --target wasm32-wasip2 --target-dir /tmp/target 2>&1 &&
    ls /tmp/target/wasm32-wasip2/release/rowstile_zed.wasm >/dev/null' \
  && ok "it builds for wasm32-wasip2" || bad "the Zed extension doesn't build"

exit $rc
