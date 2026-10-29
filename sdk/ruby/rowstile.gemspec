# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name = "rowstile"
  # lib/rowstile/version.rb, read rather than required: the gem is loaded only by what uses it
  spec.version = File.read(File.join(__dir__, "lib/rowstile/version.rb"))[/VERSION = "([^"]+)"/, 1]
  spec.summary = "Authorization for Postgres apps: access rules compiled to row-level security. The SDK for Rails apps"
  spec.description = <<~TEXT
    The SDK for Rails apps on a rowstile policy (preview): every Active Record transaction signs in as whoever the
    request or the job acts for, refused writes become a 403 with the database's reason, rows the user can't see a
    404, and the app refuses to start on a connection that skips row-level security. It holds no rowstile logic: it
    calls the authz.* functions the policy made, and translates their answers.
  TEXT
  spec.authors = ["Salaheddine EL HSSANI"]
  spec.license = "Apache-2.0"
  spec.homepage = "https://rowstile.dev"
  spec.metadata = {
    "homepage_uri" => "https://rowstile.dev",
    "documentation_uri" => "https://rowstile.dev/stacks/rails",
    "source_code_uri" => "https://github.com/rowstile/rowstile/tree/main/sdk/ruby",
    "changelog_uri" => "https://rowstile.dev/changelog",
    "bug_tracker_uri" => "https://github.com/rowstile/rowstile/issues",
    "rubygems_mfa_required" => "true",
  }
  spec.required_ruby_version = ">= 3.3"
  spec.files = Dir["lib/**/*.rb", "sig/**/*.rbs", "README.md", "LICENSE"]
  spec.require_paths = ["lib"]
  spec.add_dependency "activerecord", ">= 8.0", "< 9"
  spec.add_dependency "pg", ">= 1.5"
end
