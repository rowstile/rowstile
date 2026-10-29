# frozen_string_literal: true

require "active_record"
require "active_record/connection_adapters/postgresql_adapter"

module Rowstile
  # authz.explain_rule's answer for a row, in the same transaction and as the same user: its lines (NULL: the row
  # isn't there for this user), who is signed in, in the words the database's own refusals use ('user 2',
  # 'service 3', 'someone not signed in'), and the table as the policy names it (a table named without its schema
  # is looked up on the search_path).
  EXPLAIN = <<~SQL.tr("\n", " ")
    SELECT authz.explain_rule(t.tbl, $2, $3, NULL) AS lines,
      coalesce((SELECT p.principal_type || ' ' || p.principal_id FROM authz.principal() p), 'someone not signed in') AS who,
      t.tbl AS tbl
    FROM (SELECT coalesce((SELECT n.nspname || '.' || c.relname FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      WHERE position('.' in $1) = 0 AND c.oid = pg_catalog.to_regclass(pg_catalog.quote_ident($1))), $1) AS tbl) t
  SQL
  private_constant :EXPLAIN

  # Signs in every transaction an Active Record connection to Postgres runs while the code acts for someone
  # (Rowstile.current: a request, a job, acting_as): before the transaction's first statement, and again before the
  # next one whenever who the code acts for changed (acting_as inside a transaction, or a savepoint rolled back over
  # the sign-in); once the code acts for no one again, as nobody. A statement outside a transaction is one of its own (BEGIN, the sign-in, the statement, COMMIT),
  # as Postgres would run it alone. While the code acts for no one (the owner's migrations, a console) nothing is
  # signed in, and the database refuses what needs to know who asks (AZ701). A sign-in lasts one transaction, so a
  # pooled connection carries no one into the next.
  module SignIn
    UNSIGNED = %w[TRANSACTION SCHEMA].freeze

    def begin_db_transaction
      super
      @rowstile_signed = nil
    end

    def begin_isolated_db_transaction(isolation)
      super
      @rowstile_signed = nil
    end

    def commit_db_transaction
      super
      @rowstile_signed = nil
    end

    def exec_rollback_db_transaction
      super
      @rowstile_signed = nil
    end

    def exec_rollback_to_savepoint(name = current_savepoint_name)
      super
      @rowstile_signed = nil
    end

    def exec_restart_db_transaction
      super
      @rowstile_signed = nil
    end

    private

    # Rails names the statements that begin and end transactions and savepoints TRANSACTION, and its reads of the
    # catalog SCHEMA: neither is signed in (a ROLLBACK must go through in a transaction an error aborted, and row-level
    # security doesn't apply to the catalog)
    def raw_execute(sql, name = nil, binds = [], materialize_transactions: true, **options)
      # a transaction that signed someone in, run on by code that acts for no one: nobody, from here on
      who = Rowstile.current || (NOBODY if @rowstile_signed)
      return super if who.nil? || !materialize_transactions || UNSIGNED.include?(name)
      # (in a transaction of its own, this again: the sign-in, then the statement)
      return transaction { raw_execute(sql, name, binds, materialize_transactions:, **options) } unless transaction_open?

      self.materialize_transactions # (the method: the argument has its name)
      unless @rowstile_signed == who
        internal_execute("SELECT authz.act_as($1, $2)", "rowstile", Rowstile.act_as_args(who),
                         materialize_transactions: false)
        @rowstile_signed = who
      end
      super
    end
  end

  # An update or a delete of a record that changed no row: row-level security left it out. Asks the database why,
  # in the same transaction (before it is rolled back) and as the same user, and raises NotFound (the row is
  # hidden) or Refused (and why). A record with a lock_version the rules allow to change, which matched nothing,
  # changed since it was read: ActiveRecord::StaleObjectError, as Rails raises it (a 409). Only while the code acts
  # for someone: the owner's code is left as Rails runs it.
  module Model
    private

    def _update_row(attribute_names, attempted_action = "update")
      rowstile_expect("update") { super }
    end

    def destroy_row
      rowstile_expect("delete") { super }
    end

    def rowstile_expect(command)
      changed = yield
      return changed if changed.positive? || Rowstile.current.nil?

      rowstile_why(command, nil)
    rescue ActiveRecord::StaleObjectError => e
      raise if Rowstile.current.nil?

      rowstile_why(command, e)
    end

    def rowstile_why(command, stale)
      Rowstile.expect(0, self.class.table_name, command, id_in_database, connection: self.class.lease_connection,
                                                                          stale: stale)
    end
  end

  class << self
    # An UPDATE or DELETE's count of rows changed (update_all, delete_all, an execute's result): returned if it
    # changed something, else NotFound (the row is hidden, or didn't match) or Refused (the user may not, and
    # why). In the same transaction as the statement.
    #
    #   Rowstile.expect(Note.where(id: id).delete_all, "app.notes", "delete", id)
    def expect(changed, table, command, key, connection: ActiveRecord::Base.lease_connection, stale: nil)
      return changed if changed.positive?

      lines, who, named = connection.select_all(EXPLAIN, "rowstile", [table, command, key_text(key)]).cast_values.first
      verdict = verdict(named, command, key, lines, who)
      # a record with a lock_version, which the rules allow to change: it changed since it was read
      raise stale if stale && verdict.is_a?(NotFound) && !lines.nil?

      raise verdict
    end

    # authz.connection_check()'s rows, [severity, problem], on the app's connection (signed in as nobody).
    def connection_check(model = ActiveRecord::Base)
      acting_as(nil) do
        model.with_connection do |c|
          c.select_rows("SELECT severity, problem FROM authz.connection_check()", "rowstile")
        end
      end
    end

    # Raises ConnectionProblem if the app's connection skips row-level security (an owner's, a superuser's, a
    # role with BYPASSRLS). The Railtie runs it when the app is served (config.ru's load_server).
    def check_connection!(model = ActiveRecord::Base)
      problems = connection_check(model).select { |severity, _| severity == "error" }.map(&:last)
      raise ConnectionProblem, problems unless problems.empty?
    end
  end

  # Questions about permissions, as whoever the code acts for. Queries.new takes any name; the generated client
  # (rowstile client ruby) types it with the policy's own, so a misspelled one fails Steep:
  # Authz.queries.can("note", 1, "edit").
  class Queries
    def initialize(model = ActiveRecord::Base)
      @model = model
    end

    # Whether the user holds perm on the object (authz.can).
    def can(type, id, perm)
      @model.with_connection do |c|
        c.select_value("SELECT authz.can($1, $2, $3)", "rowstile", [type, Rowstile.key_text(id), perm])
      end == true
    end

    # Each object's permissions, for a list's buttons, in one call (authz.perms_of): {"1" => ["edit", "view"]}.
    def perms_of(type, ids)
      encoded = PG::TextEncoder::Array.new.encode(ids.map { |id| Rowstile.key_text(id) })
      @model.with_connection do |c|
        rows = c.select_all("SELECT id, perms FROM authz.perms_of($1, CAST($2 AS text[]))", "rowstile",
                            [type, encoded]).cast_values
        rows.to_h { |id, perms| [id, perms] }
      end
    end

    # The scope, filtered to the objects the user holds perm on: one set lookup (authz.list), never a call per
    # row. Project.where(...) works as the scope; its key's column is compared with the listed ids.
    def permitted(scope, type, perm)
      key = scope.model.primary_key
      cast = scope.model.columns_hash.fetch(key).sql_type
      listed = Arel.sql("SELECT CAST(x AS #{cast}) FROM authz.list(?, ?) x", type, perm)
      scope.where(scope.model.arel_table[key].in(listed))
    end
  end
end

ActiveSupport.on_load(:active_record_postgresqladapter) { |adapter| adapter.prepend(Rowstile::SignIn) }
ActiveSupport.on_load(:active_record) { |base| base.prepend(Rowstile::Model) }
