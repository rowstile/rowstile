#!/bin/bash
# The matchers' types with each Vitest the package supports (peerDependencies: 4 and 5): use.ts compiled,
# strict, in a folder with that Vitest and the built packages (npx tsc -b sdk/typescript first). Each Vitest comes
# from its folder's lock file (vitest-4/, vitest-5/: the newest of that major, kept so by Dependabot), by its hash.
#   bash sdk/typescript/vitest/types-test/types.sh [4 5]
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
SDK=$(cd "$HERE/../.." && pwd)
VERSIONS=${*:-4 5}
fails=0
for v in $VERSIONS; do
  dir=$(mktemp -d)
  cp "$HERE/use.ts" "$dir/"
  printf '{"compilerOptions": {"strict": true, "noEmit": true, "target": "ES2022", "module": "NodeNext",
    "moduleResolution": "NodeNext", "skipLibCheck": false, "types": []}, "files": ["use.ts"]}\n' > "$dir/tsconfig.json"
  cp "$HERE/vitest-$v/package.json" "$HERE/vitest-$v/package-lock.json" "$dir/"
  (cd "$dir" && npm ci --no-audit --no-fund --ignore-scripts >/dev/null 2>&1) \
    || { echo "FAIL  installing Vitest $v"; fails=$((fails + 1)); continue; }
  # the built packages, after npm (which removes what its package.json doesn't name)
  for p in client vitest; do
    mkdir -p "$dir/node_modules/@rowstile/$p"
    cp -r "$SDK/$p/package.json" "$SDK/$p/dist" "$dir/node_modules/@rowstile/$p/"
  done
  got=$(cd "$dir" && node -p 'require("./node_modules/vitest/package.json").version')
  if (cd "$dir" && npx tsc -p .); then echo "ok    the matchers' types with Vitest $got"
  else echo "FAIL  the matchers' types with Vitest $got"; fails=$((fails + 1)); fi
  rm -rf "$dir"
done
exit $((fails > 0))
