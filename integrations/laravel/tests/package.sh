#!/bin/bash
# package.sh OUT: the Composer package as it is published: composer.json validated, sdk/php archived as Composer
# archives a package (OUT/rowstile.zip: what a release's tag serves), that archive unpacked and installed by Composer
# into an empty project (OUT/app), copied in rather than linked, then loaded from there (test/installed.php says what
# it checks). test.sh runs it, in the PHP image.
set -eu
out=$1
here=$PWD
version=$(sed -n "s/^    public const VERSION = '\([^']*\)';$/\1/p" ../../sdk/php/src/Version.php)
(cd ../../sdk/php && COMPOSER_ROOT_VERSION=$version composer validate --strict --quiet &&
  COMPOSER_ROOT_VERSION=$version composer archive --quiet --format=zip --dir="$out" --file=rowstile)
rm -rf "$out/built" "$out/app" && mkdir -p "$out/built" "$out/app"
unzip -q "$out/rowstile.zip" -d "$out/built"
cat >"$out/app/composer.json" <<JSON
{
    "require": {"rowstile/rowstile": "$version"},
    "repositories": [{"type": "path", "url": "$out/built", "options": {"symlink": false, "versions": {"rowstile/rowstile": "$version"}}}],
    "minimum-stability": "dev"
}
JSON
(cd "$out/app" && composer install --quiet --no-interaction)
cd "$out/app" && php "$here/tests/installed.php" "$out/app/vendor/rowstile/rowstile" "$version"
