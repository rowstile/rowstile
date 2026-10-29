# frozen_string_literal: true

require "pg"
require "rowstile"

module Rowstile
  # Minitest helpers for apps on rowstile (ActiveSupport::TestCase, ActionDispatch::IntegrationTest).
  #
  #   class NotesTest < ActiveSupport::TestCase
  #     include Rowstile::Testing
  #
  #     test "cy may not rename ann's note" do
  #       as_user(3) { assert_refused(command: "update") { Note.find(1).update!(body: "x") } }
  #     end
  #   end
  #
  # A database per worker (parallelize): Rowstile::Testing.database_per_worker(owner_url, worker) copies the migrated
  # test database (with the policy) once for each worker, and connects the app to the copy. Rails' own way, loading
  # db/structure.sql into each, can't make one: the dump leaves out the grants and the policy's own rows.
  module Testing
    # Everything in the block acts for who (42, ["service", 3], nil for nobody).
    def as_user(who, &)
      Rowstile.acting_as(who, &)
    end

    # The block must be refused by the policy (by the rule for command, on table, when given); returns the Refused.
    def assert_refused(command: nil, table: nil)
      yield
    rescue Refused, ActiveRecord::StatementInvalid => e
      refused = e.is_a?(Refused) ? e : Rowstile.refusal(e)
      raise e if refused.nil?

      if command
        assert refused.command.to_s.start_with?(command),
               "expected the #{command} rule to refuse it, but: #{refused.command}: #{refused.message}"
      end
      assert_equal table, refused.table if table
      refused
    else
      flunk "expected a refusal"
    end

    # The block must raise NotFound (or ActiveRecord::RecordNotFound: the row is hidden); returns it.
    def assert_not_found(&)
      assert_raises(NotFound, ActiveRecord::RecordNotFound, &)
    end

    # A database for this worker, copied from the one owner_url names (migrated, with the policy), made again if an
    # earlier run left one; then the app's connection (its role, its settings) goes to the copy. Its name: the
    # original's and the worker's number, as Rails names a worker's database (conf_tests_0). The copy is made by a
    # role that may create databases (the owner), while nothing is connected to the original.
    #
    #   parallelize_setup { |worker| Rowstile::Testing.database_per_worker(ENV["ROWSTILE_TESTS_URL"], worker) }
    def self.database_per_worker(owner_url, worker = 0)
      template = PG::Connection.conninfo_parse(owner_url).to_h { |o| [o[:keyword], o[:val]] }["dbname"]
      raise ArgumentError, "database_per_worker needs a database to copy, and this URL names none" if template.nil?

      name = "#{template}_#{worker}"
      conn = PG.connect(owner_url, dbname: "postgres")
      begin
        conn.exec("SET client_min_messages = warning")
        conn.exec("DROP DATABASE IF EXISTS #{conn.quote_ident(name)} WITH (FORCE)")
        conn.exec("CREATE DATABASE #{conn.quote_ident(name)} TEMPLATE #{conn.quote_ident(template)}")
      rescue PG::ObjectInUse => e
        raise "rowstile: #{template} can't be copied while anything is connected to it: close what holds it (the " \
              "app, a migration, a console). (#{e.message.strip})"
      ensure
        conn.close
      end
      ActiveRecord::Base.establish_connection(ActiveRecord::Base.connection_db_config.configuration_hash
                                                .merge(database: name))
      name
    end
  end
end
