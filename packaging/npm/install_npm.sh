#!/bin/bash
# The npm the release publishes with: moving a tag by trusted publishing needs 11.21.0 or newer, newer than Node 24
# brings. Its tarball from the registry, checked against the hash below, then installed globally by itself from that
# same file: nothing else is fetched (npm bundles what it needs). The registry gives the tarball's sha512 as
#   sha512-Zov8KhamNneiLdELtj5YALtNmJW4L4fCLTzjfpzXG2w6MSHcf0UxgdlK5uloCuksWT+7mGUU7wi79cO6RqivPg==
# (npm view npm@11.21.0 dist.integrity); a new version changes both lines.
#   bash packaging/npm/install_npm.sh
set -eu
VERSION=11.21.0
SHA256=783e7c92bf73b442fb800c2d6ef3921e86da8894a700fed45140e37916877482
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
curl -fsSLo "$dir/npm.tgz" "https://registry.npmjs.org/npm/-/npm-$VERSION.tgz"
echo "$SHA256  $dir/npm.tgz" | sha256sum -c --quiet -
tar -xzf "$dir/npm.tgz" -C "$dir"
node "$dir/package/bin/npm-cli.js" install --global --no-audit --no-fund "$dir/npm.tgz"
echo "npm $(npm --version)"
