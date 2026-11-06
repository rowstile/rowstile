# frozen_string_literal: true

require "active_support"
require "active_support/isolated_execution_state"
require "pg"
require_relative "rowstile/version"

# rowstile for Rails apps (preview).
#
# Every Active Record transaction signs in as whoever the code acts for, with authz.act_as(); the database's
# refusals become Rowstile::Refused (a 403 with the reason), rows the user can't see Rowstile::NotFound (a 404).
# The gem holds no rowstile logic: it calls the authz.* functions the policy made, and translates their answers.
#
#   Rowstile.acting_as(42) { Note.count }      # or ["service", 3], or nil for nobody
#
# In a Rails app the gem's Railtie does the rest: a middleware sets who each request acts for
# (config.rowstile.user), and answers refusals with problem+json; the app refuses to boot on a connection that
# skips row-level security. Rowstile::Job signs Active Job jobs in; Rowstile::Testing helps Minitest.
module Rowstile
  # Who a transaction acts for: a user (type "user"), another principal type the policy declares (a service, a
  # bot), or nobody (id nil: only what `anyone` may see). Nobody has one spelling: a principal made without an id
  # (nil or ""), whatever its type, is NOBODY, as the database signs it in.
  class Principal
    attr_reader :type, :id

    def initialize(type:, id:)
      nobody = id.to_s.empty?
      @type = nobody ? "user" : type
      @id = nobody ? nil : id
      freeze
    end

    # 42 or "42" (a user, whatever the id holds), ["service", 3], a Principal, or nil (nobody). A plain id is a
    # user's: "service:3" is the user whose id that is (ids often come from outside), never service 3.
    def self.of(who)
      case who
      when Principal then who
      when nil then NOBODY
      when Array then new(type: who[0].to_s, id: who[1]&.to_s)
      else new(type: "user", id: who.to_s)
      end
    end

    # What to_s wrote, read back: "service:3" is service 3, "42" and "user:42" user 42, "nobody" nobody. For text
    # the app's own code wrote (a job's argument) and for who acted in the audit trail, which the database writes
    # the same way; not for an id that came from outside.
    def self.parse(text)
      return NOBODY if text == "nobody"
      return new(type: "user", id: text) if !text.include?(":") || text.start_with?("(")

      kind, id = text.split(":", 2)
      new(type: kind.to_s, id: id.to_s)
    end

    # "42", "service:3" or "nobody". A user whose id holds ":" or is "nobody" is "user:<id>", so that parse reads
    # every principal back as itself.
    def to_s
      id = @id
      return "nobody" if id.nil?
      return "#{type}:#{id}" if type != "user"

      id.include?(":") || id == "nobody" ? "user:#{id}" : id
    end

    def ==(other)
      other.is_a?(Principal) && type == other.type && id == other.id
    end
    alias eql? ==

    def hash = [type, id].hash
    def inspect = "#<Rowstile::Principal #{self}>"
  end

  NOBODY = Principal.new(type: "user", id: nil)
  KEY = :rowstile_principal
  private_constant :KEY

  class << self
    # Who the code running now acts for (a request, a job, acting_as), or nil when nothing set it: a transaction
    # begun then isn't signed in, and the database refuses what needs to know who asks (AZ701).
    def current
      ActiveSupport::IsolatedExecutionState[KEY]
    end

    # Every transaction begun in the block signs in as who (nil: nobody). A transaction is one principal's: inside
    # one signed in as someone else already, the block's first statement raises, and nothing is sent for it.
    # Active Record's query cache is emptied as the block begins and ends: what it kept was read as someone else.
    def acting_as(who)
      before = current
      ActiveSupport::IsolatedExecutionState[KEY] = Principal.of(who)
      ActiveRecord::Base.clear_query_caches_for_current_thread
      begin
        yield
      ensure
        ActiveSupport::IsolatedExecutionState[KEY] = before
        ActiveRecord::Base.clear_query_caches_for_current_thread
      end
    end

    # authz.act_as's arguments, [type, id]: ["user", "42"], or [nil, nil] for nobody.
    def act_as_args(who)
      p = Principal.of(who)
      p.id.nil? ? [nil, nil] : [p.type, p.id]
    end
  end

  # The database refused a write, and said why: the rule (table and command), and the explanation.
  class Refused < StandardError
    attr_reader :table, :command, :why, :code

    def initialize(message, table: nil, command: nil, why: [], code: nil)
      super(message)
      @table = table
      @command = command
      @why = why
      @code = code || "AZ709" # rowstile help AZ709: a rule's refusal; the database's own for another (AZ705)
    end

    def problem
      {
        "type" => "https://rowstile.dev/problems/refused", "title" => "Forbidden", "status" => 403,
        "detail" => message, "table" => table, "command" => command, "why" => why, "code" => code,
      }
    end
  end

  # The row isn't there, or whoever the transaction acts for can't see it.
  class NotFound < StandardError
    attr_reader :table, :id

    def initialize(table = nil, id = nil)
      @table = table
      @id = Rowstile.key_text(id)
      named = @id.nil? ? [table].compact : [table || "row", @id]
      super([*named, "not found"].join(" "))
    end

    def problem
      { "type" => "https://rowstile.dev/problems/not-found", "title" => "Not Found", "status" => 404,
        "detail" => message }
    end
  end

  # A query that needs to know who is asking ran in a transaction nobody signed in to (rowstile help AZ701).
  class NotSignedIn < StandardError
    def code = "AZ701"
  end

  # authz.connection_check() found that the app's connection skips row-level security (or worse).
  class ConnectionProblem < StandardError
    attr_reader :problems

    def initialize(problems)
      @problems = problems
      super("the app's database connection can't be used with rowstile: #{problems.join("; ")}")
    end
  end

  # rowstile's codes for a call the database turned down that is no refusal, and what their pages say to answer
  # (rowstile help AZ703: a login refused; AZ708: what the call names isn't there; AZ710: a missing or wrong
  # argument; AZ713: moved inside itself; AZ714: sign in first)
  CALL_PROBLEMS = {
    "AZ703" => ["https://rowstile.dev/problems/not-signed-in", "Unauthorized", 401],
    "AZ708" => ["https://rowstile.dev/problems/not-found", "Not Found", 404],
    "AZ710" => ["https://rowstile.dev/problems/bad-argument", "Bad Request", 400],
    "AZ713" => ["https://rowstile.dev/problems/conflict", "Conflict", 409],
    "AZ714" => ["https://rowstile.dev/problems/not-signed-in", "Unauthorized", 401],
  }.freeze #: Hash[String, [String, String, Integer]]

  # An update the rules allow that matched no row: the row changed since it was read (a lock_version)
  CONFLICT = {
    "type" => "https://rowstile.dev/problems/conflict", "title" => "Conflict", "status" => 409,
    "detail" => "the row changed since it was read, and the rules allow the change: read it again",
  }.freeze

  UNSEEN = "this user may not see the row as written (the select rule). An insert that reads it back " \
           "(RETURNING), an upsert, and an update with a WHERE need to see it."
  GENERIC = /\A(new|target) row violates row-level security policy (\(USING expression\) )?for table "([^"]+)"/
  # the function in Postgres that raises those refusals (the error's source function): what tells one in another
  # language
  ROW_CHECK = "ExecWithCheckOptions"
  private_constant :UNSEEN, :GENERIC, :ROW_CHECK

  # What the database said, from the error or the driver's error inside it (Active Record keeps PG's as the cause).
  class Said
    attr_reader :sqlstate, :message, :detail, :hint, :schema, :table, :constraint, :routine

    def initialize(result)
      @sqlstate = result.error_field(PG::PG_DIAG_SQLSTATE)
      @message = result.error_field(PG::PG_DIAG_MESSAGE_PRIMARY).to_s
      @detail = result.error_field(PG::PG_DIAG_MESSAGE_DETAIL)
      @hint = result.error_field(PG::PG_DIAG_MESSAGE_HINT)
      @schema = result.error_field(PG::PG_DIAG_SCHEMA_NAME)
      @table = result.error_field(PG::PG_DIAG_TABLE_NAME)
      @constraint = result.error_field(PG::PG_DIAG_CONSTRAINT_NAME)
      @routine = result.error_field(PG::PG_DIAG_SOURCE_FUNCTION)
    end

    def self.of(error)
      result = pg_error(error)&.result
      result && new(result)
    end

    # the error, or the first of its causes that is the driver's
    def self.pg_error(error)
      case error
      when PG::Error, nil then error
      else pg_error(error.cause)
      end
    end

    # rowstile's code, from the HINT, where the runtime puts it (rowstile help AZ709), and never the message, which
    # may hold the request's own input (Postgres's own words quote a value it couldn't read)
    def code
      hint.to_s[/rowstile help (AZ\d{3})/, 1]
    end
  end
  private_constant :Said

  class << self
    # rowstile's code for a database error (AZ709: `rowstile help AZ709` says what it means), nil for an error
    # rowstile didn't raise.
    def error_code(error)
      Said.of(error)&.code
    end

    # The error's SQLSTATE, nil for an error that isn't the database's.
    def sqlstate(error)
      Said.of(error)&.sqlstate
    end

    # Whether error is strict sign-in's (rowstile help AZ701): a query that needs to know who is asking ran in a
    # transaction nobody signed in to. Its SQLSTATE, 28000, is shared by a login refused (AZ703), settings changed
    # by hand (AZ702) and Postgres's own refusals to connect (a role that isn't there, pg_hba.conf), which carry no
    # code: none of them is.
    def not_signed_in?(error)
      said = Said.of(error)
      !said.nil? && said.sqlstate == "28000" && said.code == "AZ701"
    end

    # A Refused for an error that is the database refusing a write (SQLSTATE 42501, raised by rowstile's policies
    # with the rule and why, or Postgres's own words for the select rule), else nil. Another 42501 (a table the app
    # role was never granted) is the app's mistake, not a refusal.
    def refusal(error)
      said = Said.of(error)
      return nil if said.nil? || said.sqlstate != "42501"

      generic = GENERIC.match(said.message)
      code = said.code
      # Postgres's own refusal in another language (the server's lc_messages): which table and rule, its words alone say
      return Refused.new(said.message) if code.nil? && generic.nil? && said.routine == ROW_CHECK
      return nil if (code.nil? && generic.nil?) || CALL_PROBLEMS.key?(code) # sign in first (AZ714) is a 401
      return generic_refusal(said.message, generic) if generic

      schema, table, constraint = said.schema, said.table, said.constraint
      Refused.new(said.message, table: schema && table ? "#{schema}.#{table}" : table,
                                command: constraint&.start_with?("authz_") ? constraint.delete_prefix("authz_") : nil,
                                why: said.detail.to_s.split("\n"), code: code)
    end

    # The problem body for a database error that is no refusal and answers as its code's page says: a login
    # refused or a call that needs someone signed in 401 (AZ703, AZ714), what the call names isn't there 404
    # (AZ708), an argument missing or wrong 400 (AZ710), a move inside itself 409 (AZ713); nil for any other.
    def call_problem(error)
      said = Said.of(error)
      kind, title, status = CALL_PROBLEMS[said&.code]
      return nil if said.nil? || kind.nil?

      { "type" => kind, "title" => title, "status" => status, "detail" => said.message, "code" => said.code }
    end

    # The problem body for an error, or nil when it is none of rowstile's answers (the app's to answer). A query
    # in a transaction nobody signed in to is the app's bug: NotSignedIn, which says how. (The Railtie's middleware
    # answers with it; an app without Rails may too.)
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

    # A row's key as Postgres writes it: 7, or (1,2) for a composite key, an Array of its values (a field quoted only
    # where Postgres would: empty, or holding a comma, a quote, a backslash, a parenthesis or one of ASCII's six
    # spaces, and for no other character).
    def key_text(key)
      key = key.first if key.is_a?(Array) && key.length == 1
      return "(#{key.map { |v| field_text(v) }.join(",")})" if key.is_a?(Array)

      key&.to_s
    end

    # What an UPDATE or DELETE that changed nothing was, from authz.explain_rule's answer (lines nil: the row isn't
    # there for this user; a first line saying yes: the rule allows it and the statement matched nothing for
    # another reason): NotFound, or Refused with why. Worded as the database words a refused insert.
    def verdict(table, command, key, lines, who)
      return NotFound.new(table, key) if lines.nil? || lines.first.to_s.lstrip.start_with?("yes")

      Refused.new("permission denied: #{who} may not #{command} row #{key_text(key)} of #{table}",
                  table: table, command: command, why: lines)
    end

    private

    # the table of the model Active Record names ("Note": app.notes)
    def table_of(model)
      found = model && ActiveSupport::Inflector.safe_constantize(model)
      found.table_name if found.is_a?(Class) && found < ActiveRecord::Base
    end

    def field_text(value)
      return "" if value.nil?

      text = value.to_s
      return text unless text.empty? || text.match?(/[",\\() \t\n\r\v\f]/)

      %("#{text.gsub("\\") { "\\\\" }.gsub('"', '""')}")
    end

    def generic_refusal(message, match)
      row, existing, name = match.captures
      if row == "target" # MERGE matched a row the update or the delete rule hides; Postgres doesn't say which
        return Refused.new("#{message}: MERGE matched a row the update or delete rule doesn't let this user change",
                           table: name)
      end
      if existing # an upsert whose existing row this user may not update, or not see
        return Refused.new("#{message}: the row is there already, and the update rule (or the select rule) doesn't " \
                           "let this user change it (ON CONFLICT DO UPDATE)", table: name, command: "update")
      end
      Refused.new("#{message}: #{UNSEEN}", table: name, command: "select")
    end
  end
end

require_relative "rowstile/active_record"
require_relative "rowstile/job"
require_relative "rowstile/schema"
require_relative "rowstile/railtie" if defined?(Rails::Railtie)
