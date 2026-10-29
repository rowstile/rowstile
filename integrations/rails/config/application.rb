# frozen_string_literal: true

require_relative "boot"
require "rails"
require "active_record/railtie"
require "action_controller/railtie"
require "active_job/railtie"
Bundler.require(*Rails.groups)

module Conformance
  # The conformance app: no permission checks anywhere. rowstile signs each request's transactions in, the
  # database filters reads and refuses writes, and the gem turns refusals into 403 and hidden rows into 404.
  class Application < Rails::Application
    config.load_defaults 8.1
    config.api_only = true
    config.eager_load = false
    config.logger = Logger.new(nil)
    # who each request acts for: the request's signed-in user (nil: nobody), or a service
    config.rowstile.user = ->(request) { SessionUser.call(request) }
    # db/structure.sql, not db/schema.rb: schema.rb doesn't hold row-level security (nor triggers, nor functions),
    # so its diff would never show a policy change. The app's schemas only: rowstile's own are its migrations'
    config.active_record.schema_format = :sql
    config.active_record.dump_schemas = "app"
  end
end
