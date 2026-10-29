# frozen_string_literal: true

require "rails/railtie"
require_relative "middleware"

module Rowstile
  # Wires rowstile into a Rails app: the middleware (each request acts for config.rowstile.user.call(request)), and
  # the start-up check, run when the app is served (config.ru's Rails.application.load_server, which `rails server`,
  # Puma and every Rack server run; not a rake task, nor the console): the app refuses to start on a connection that
  # skips row-level security. config.rowstile.check_connection = false leaves the check out.
  #
  #   # config/application.rb
  #   config.rowstile.user = ->(request) { request.session[:user_id] }
  class Railtie < Rails::Railtie
    config.rowstile = ActiveSupport::OrderedOptions.new
    config.rowstile.check_connection = true

    initializer "rowstile.middleware" do |app|
      app.middleware.use Rowstile::Middleware, user: ->(request) { app.config.rowstile.user&.call(request) }
    end

    server do |app|
      Rowstile.check_connection! if app.config.rowstile.check_connection
    end
  end
end
