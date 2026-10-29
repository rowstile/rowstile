# frozen_string_literal: true

# The installed gem (test/gem.sh), loaded without Bundler: it comes from where it was installed, holds its
# signatures and its integrations, and says its version.
gem "rowstile"
require "rowstile"
where = $LOADED_FEATURES.grep(%r{/rowstile\.rb\z})
abort "rowstile was loaded from #{where.join(", ")}, not from #{ARGV[0]}" unless where.all? { |f| f.start_with?(ARGV[0]) }
spec = Gem.loaded_specs.fetch("rowstile")
# (an installed gem's specification lists no files: what it holds is on disk)
missing = %w[lib/rowstile/railtie.rb lib/rowstile/testing.rb sig/rowstile.rbs README.md LICENSE].reject do |f|
  File.file?(File.join(spec.full_gem_path, f))
end
abort "the gem lacks #{missing.join(", ")}" unless missing.empty?
abort "#{spec.version} isn't #{Rowstile::VERSION}" unless spec.version == Gem::Version.new(Rowstile::VERSION)
puts spec.version
