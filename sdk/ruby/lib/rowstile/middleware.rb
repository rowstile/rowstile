# frozen_string_literal: true

require "json"
require "action_dispatch"

module Rowstile
  # A Rack middleware: each request acts for user.call(request) (a user's id, ["service", 3], a Principal, or nil
  # for nobody), so every transaction it begins signs in as them; a refused write answers 403 with the reason (an
  # RFC 9457 problem body), a row the user can't see 404 (ActiveRecord::RecordNotFound too), and a call the
  # database turns down that is no refusal as its code's page says. The Railtie adds it; config.rowstile.user is
  # user.
  class Middleware
    def initialize(app, user: nil)
      @app = app
      @user = user
    end

    def call(env)
      who = @user&.call(ActionDispatch::Request.new(env))
      Rowstile.acting_as(who) { @app.call(env) }
    rescue Refused, NotFound, ActiveRecord::ActiveRecordError => e
      problem = Rowstile.problem_of(e)
      raise unless problem

      status = problem.fetch("status") #: Integer
      [status, { "content-type" => "application/problem+json" }, [JSON.generate(problem)]]
    end
  end
end
