# frozen_string_literal: true

require_relative "config/environment"

run Rails.application
# runs the Railties' server blocks: rowstile's refuses to serve on a connection that skips row-level security
Rails.application.load_server
