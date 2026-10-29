#!/bin/bash
# gem.sh OUT: the gem built from sdk/ruby (OUT/rowstile.gem), installed from that file alone into OUT/gems, then
# loaded from there, outside Bundler, with the gems it needs from the bundle (test/installed_gem.rb says what
# it checks). test.sh runs it.
set -eu
out=$1
here=$PWD
(cd ../../sdk/ruby && gem build -q rowstile.gemspec -o "$out/rowstile.gem" >/dev/null)
gem install -q --local --ignore-dependencies --no-document --install-dir "$out/gems" "$out/rowstile.gem" >/dev/null
deps=$(bundle exec ruby -e 'print Gem.path.join(":")')
cd "$out" && GEM_PATH="$out/gems:$deps" ruby "$here/test/installed_gem.rb" "$out/gems"
