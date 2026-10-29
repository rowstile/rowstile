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

  class << self
    # The problem body for an error, or nil when it is none of rowstile's answers (the app's to answer). A query
    # in a transaction nobody signed in to is the app's bug: NotSignedIn, which says how.
    def problem_of(error)
      case error
      when Refused, NotFound then error.problem
      when ActiveRecord::RecordNotFound then NotFound.new(table_of(error.model), error.id).problem
      when ActiveRecord::StaleObjectError then CONFLICT
      else
        found = refusal(error)&.problem || call_problem(error)
        if found.nil? && not_signed_in?(error)
          raise NotSignedIn, "a query ran in a transaction nobody signed in to: every transaction must begin with " \
                             "authz.act_as() (rowstile signs in Active Record's while the code acts for someone: a " \
                             "request, a job, Rowstile.acting_as)"
        end
        found
      end
    end

    private

    # the table of the model Active Record names ("Note": app.notes)
    def table_of(model)
      found = model && ActiveSupport::Inflector.safe_constantize(model)
      found.table_name if found.is_a?(Class) && found < ActiveRecord::Base
    end
  end
end
