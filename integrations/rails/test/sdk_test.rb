# frozen_string_literal: true

require "test_helper"
require "fileutils"

# The gem's own calls, each way they can go, beyond the conformance checks: what each promises, asked of the
# database where there is one to ask. test.sh measures what these and the checks run of the gem, and fails unless
# they run every line and branch of it.
class SdkTest < ActionDispatch::IntegrationTest
  setup { Rows.load! }

  def json = JSON.parse(response.body)

  def ids(sql = "SELECT id FROM app.notes ORDER BY id")
    ApplicationRecord.with_connection { |c| c.select_values(sql) }
  end

  class OwnerRecord < ActiveRecord::Base
    self.abstract_class = true
  end

  class OwnerNote < OwnerRecord
    self.table_name = "app.notes"
  end

  def as_owner
    OwnerRecord.establish_connection(Rows.owner_config)
    yield
  ensure
    OwnerRecord.remove_connection
  end

  # queries by permission: one set lookup, and one call for a list's buttons
  test "queries by permission" do
    get "/projects/editable", headers: as("3")
    assert_equal [1], json
    get "/projects/buttons", headers: as("3")
    assert_equal({ "1" => %w[edit view], "3" => ["view"] }, json)
    Rowstile.acting_as(3) do
      assert Authz.queries.can("note", 4, "edit")
      assert_not Authz.queries.can("note", 1, "edit")
    end
  end

  # a transaction is one principal's: inside one signed in already, a statement while the code acts for someone else
  # (nobody too) raises before anything is sent for it, the transaction as it was. The same principal goes on (in a
  # savepoint too), and the transaction reads, writes and commits as its own
  test "a transaction is one principal's" do
    Note.load_schema # (what Rails reads of the catalog first: the columns, then the table and its key, for find)
    Note.primary_key
    sent = []
    log = ->(*, payload) { sent << payload[:sql] }
    seen = Rowstile.acting_as(1) do
      ApplicationRecord.cache do
        Note.transaction do
          first = ids
          same = Rowstile.acting_as(1) { Note.transaction(requires_new: true) { ids } }
          refused = ActiveSupport::Notifications.subscribed(log, "sql.active_record") do
            [assert_raises(RuntimeError) { Rowstile.acting_as(2) { ids } },
             assert_raises(RuntimeError) { Rowstile.acting_as(["service", 1]) { Note.transaction(requires_new: true) { ids } } },
             assert_raises(RuntimeError) { Rowstile.acting_as(nil) { Note.find(3) } }]
          end
          Note.find(1).update!(body: "ann's")
          [first, same, refused, ids, ids("SELECT current_setting('authz.user_id')")]
        end
      end
    end
    assert_equal [], sent
    first, same, refused, last, signed = seen
    assert_equal [EXPECTED["1"], EXPECTED["1"], EXPECTED["1"], ["1"]], [first, same, last, signed]
    assert_equal [RuntimeError] * 3, refused.map(&:class)
    assert_equal "this transaction is signed in as user 1 already, and a sign-in lasts the database transaction: " \
                 "user 2's work can't run inside it. Run it after, or in a transaction of its own (another connection)",
                 refused[0].message
    assert_includes refused[1].message, "as user 1 already, and a sign-in lasts the database transaction: service 1's work can't"
    assert_includes refused[2].message, "as user 1 already, and a sign-in lasts the database transaction: nobody's work can't"
    assert_equal "ann's", Rows.owner { |c| c.exec("SELECT body FROM app.notes WHERE id = 1").getvalue(0, 0) } # committed
  end

  # a transaction begun while the code acted for no one, which signed someone in: code that acts for no one again
  # can't run on in it (before the sign-in it could), and the next transaction is no one's
  test "code that acts for no one can't run on in a transaction signed in" do
    seen = Note.transaction do
      plain = ids("SELECT 1") # not signed in: acts for no one
      ann = Rowstile.acting_as(1) { ids }
      after = assert_raises(RuntimeError) { ids }
      [plain, ann, after.message, Rowstile.acting_as(1) { ids }]
    end
    assert_equal [[1], EXPECTED["1"], EXPECTED["1"]], seen.values_at(0, 1, 3)
    assert_equal "this transaction is signed in as user 1 already, and a sign-in lasts the database transaction: the " \
                 "work of code that acts for no one can't run inside it. Run it after, or in a transaction of its own " \
                 "(another connection)", seen[2]
    assert_raises(ActiveRecord::StatementInvalid) { Note.count } # and the next transaction is no one's: refused
  end

  # a savepoint rolled back over the sign-in undoes it in Postgres: the same principal signs in again, and another is
  # still refused; the same after a transaction Rails restarts (ROLLBACK AND CHAIN); a transaction with an isolation
  # level signs in too
  test "a sign-in a rollback undid is made again, for the same principal" do
    seen = Note.transaction do
      ids("SELECT 1") # (so that the next one is a savepoint)
      Note.transaction(requires_new: true) do
        Rowstile.acting_as(1) { ids }
        raise ActiveRecord::Rollback
      end
      undone = ApplicationRecord.with_connection do |c|
        c.raw_connection.exec("SELECT coalesce(current_setting('authz.user_id', true), '')").getvalue(0, 0)
      end
      [undone, Rowstile.acting_as(1) { ids }, assert_raises(RuntimeError) { Rowstile.acting_as(2) { ids } }.message]
    end
    assert_equal ["", EXPECTED["1"]], seen[0..1]
    assert_includes seen[2], "signed in as user 1 already"
    assert_equal EXPECTED["2"], Rowstile.acting_as(2) { Note.transaction(isolation: :repeatable_read) { ids } }
    restarted = Rowstile.acting_as(3) do
      Note.transaction do
        Note.transaction(requires_new: true) do
          ids
          raise ActiveRecord::Rollback
        end
        [ids, assert_raises(RuntimeError) { Rowstile.acting_as(2) { ids } }.message]
      end
    end
    assert_equal EXPECTED["3"], restarted[0]
    assert_includes restarted[1], "signed in as user 3 already"
  end

  # the console's sandbox begins its transaction as a test's is begun (on the connection, not joinable, rolled back
  # at the end): what runs in it goes as in a test's
  test "a transaction begun as the console's sandbox begins one" do
    ApplicationRecord.with_connection do |c|
      c.begin_transaction(joinable: false)
      assert_equal [EXPECTED["1"], EXPECTED["2"]], [Rowstile.acting_as(1) { ids }, Rowstile.acting_as(2) { ids }]
    ensure
      c.rollback_transaction
    end
  end

  # while the code acts for no one, nothing is signed in: the app's role is refused (strict sign-in), and the owner's
  # code runs as Rails runs it (an update that matched nothing is no error, a stale one is Rails' own)
  test "acting for no one signs nothing in" do
    error = assert_raises(ActiveRecord::StatementInvalid) { Note.count }
    assert Rowstile.not_signed_in?(error)
    assert_raises(Rowstile::NotSignedIn) { Rowstile.problem_of(error) }
    assert_equal "AZ701", Rowstile::NotSignedIn.new.code
    as_owner do
      gone = OwnerNote.find(3)
      stale = OwnerNote.find(4)
      OwnerNote.where(id: 3).delete_all
      OwnerNote.where(id: 4).update_all("lock_version = lock_version + 1")
      OwnerNote.lock_optimistically = false # (no lock: an update of a row that isn't there changes nothing)
      assert gone.update(body: "x")
      OwnerNote.lock_optimistically = true
      assert_raises(ActiveRecord::StaleObjectError) { stale.update!(body: "x") }
    ensure
      OwnerNote.lock_optimistically = true
    end
  end

  # an update the rules allow of a row that changed since it was read (its lock_version): 409, as Rails answers it
  test "an update the rules allow that matched nothing is 409" do
    meanwhile = ->(_note) { Rows.owner { |c| c.exec("UPDATE app.notes SET lock_version = lock_version + 1 WHERE id = 4") } }
    Note.set_callback(:update, :before, meanwhile)
    begin
      patch "/notes/4", params: { body: "x" }, headers: as("3"), as: :json
    ensure
      Note.skip_callback(:update, :before, meanwhile)
    end
    assert_equal 409, response.status, response.body
    assert_equal Rowstile::CONFLICT, json
  end

  # a model without a lock_version, whose row is hidden between the read and the update: 404
  test "a row without a lock_version hidden before the update is 404" do
    meanwhile = ->(_folder) { Rows.owner { |c| c.exec("UPDATE app.folders SET owner_id = 2, parent_id = NULL WHERE id = 2") } }
    Folder.set_callback(:update, :before, meanwhile)
    begin
      patch "/folders/2", params: { parent_id: nil }, headers: as("1"), as: :json
    ensure
      Folder.skip_callback(:update, :before, meanwhile)
    end
    assert_equal 404, response.status, response.body
    assert_equal "app.folders 2 not found", json["detail"]
  end

  # expect, for update_all and delete_all: the count if it changed something, else NotFound or Refused
  test "expect turns 0 rows into the database's answer" do
    Rowstile.acting_as(2) do
      assert_not_found { Rowstile.expect(Note.where(id: 1).delete_all, "app.notes", "delete", 1) }
    end
    Rowstile.acting_as(3) do
      refused = assert_refused(command: "update", table: "app.notes") do
        Rowstile.expect(Note.where(id: 1).update_all(body: "x"), "app.notes", "update", 1)
      end
      assert_equal "permission denied: user 3 may not update row 1 of app.notes", refused.message
      # the rule allows it, and the statement matched nothing for another reason (a where with more than the key)
      assert_not_found { Rowstile.expect(Note.where(id: 4, body: "no").update_all(body: "x"), "app.notes", "update", 4) }
      assert_equal 1, Rowstile.expect(Note.where(id: 4).update_all(body: "x"), "app.notes", "update", 4)
    end
    Rowstile.acting_as(nil) do # a table named without its schema is found on the search_path
      ApplicationRecord.with_connection { |c| c.execute("SET search_path = app") }
      found = assert_not_found { Rowstile.expect(0, "notes", "delete", 1) }
      assert_equal "app.notes 1 not found", found.message
    ensure
      ApplicationRecord.with_connection { |c| c.execute("RESET search_path") }
    end
  end

  # Postgres's own words, for a row no rule's own refusal covers: an upsert whose row is there, a MERGE
  test "Postgres's own refusals name the rule" do
    Rowstile.acting_as(3) do
      upsert = assert_refused(command: "update") do
        ApplicationRecord.with_connection do |c|
          c.execute("INSERT INTO app.notes (id, project_id, author_id, body) VALUES (1, 1, 3, 'x') " \
                    "ON CONFLICT (id) DO UPDATE SET body = 'x'")
        end
      end
      assert_includes upsert.message, "ON CONFLICT DO UPDATE"
      merge = assert_raises(ActiveRecord::StatementInvalid) do
        ApplicationRecord.with_connection do |c|
          c.execute("MERGE INTO app.notes n USING (SELECT 1 AS id) s ON n.id = s.id " \
                    "WHEN MATCHED THEN UPDATE SET body = 'x'")
        end
      end
      assert_includes Rowstile.refusal(merge).message, "MERGE matched a row"
      # and a 42501 that is no policy's: a table the app role was never granted
      denied = assert_raises(ActiveRecord::StatementInvalid) { ids("SELECT * FROM public.schema_migrations") }
      assert_nil Rowstile.refusal(denied)
      assert_raises(ActiveRecord::StatementInvalid) { assert_refused { ids("SELECT * FROM public.schema_migrations") } }
    end
  end

  # what isn't a database's error has no code, no SQLSTATE, no refusal and no problem
  test "an error that isn't the database's" do
    error = RuntimeError.new("no")
    assert_equal [nil, nil, nil, nil, false], [Rowstile.error_code(error), Rowstile.sqlstate(error),
                                               Rowstile.refusal(error), Rowstile.call_problem(error),
                                               Rowstile.not_signed_in?(error)]
    raw = ActiveRecord::StatementInvalid.new("no") # (no driver's error inside)
    assert_nil Rowstile.problem_of(raw)
    app = Rowstile::Middleware.new(->(_env) { raise raw })
    assert_raises(ActiveRecord::StatementInvalid) { app.call(Rack::MockRequest.env_for("/")) }
    # a not-found Active Record raises for a model that isn't one, or for none
    assert_equal "not found", Rowstile.problem_of(ActiveRecord::RecordNotFound.new("x"))["detail"]
    assert_equal "row 7 not found", Rowstile.problem_of(ActiveRecord::RecordNotFound.new("x", "String", "id", 7))["detail"]
    assert_equal "app.notes 7 not found", Rowstile.problem_of(ActiveRecord::RecordNotFound.new("x", "Note", "id", 7))["detail"]
  end

  # a middleware given no user acts for nobody; the Railtie's, with no config.rowstile.user, for nobody too
  test "requests without a user act for nobody" do
    seen = Rowstile::Middleware.new(->(_env) { [200, {}, [Rowstile.current.to_s]] }).call(Rack::MockRequest.env_for("/"))
    assert_equal [200, {}, ["nobody"]], seen
    user = Rails.application.config.rowstile.user
    Rails.application.config.rowstile.user = nil
    get "/notes", headers: as("1")
    assert_equal EXPECTED[nil], json
  ensure
    Rails.application.config.rowstile.user = user
  end

  # a key as Postgres writes it, a not-found's words, and a refusal of no line
  test "keys, words and verdicts" do
    shown = [7, [7], [1, 2], ["a b", "x,y"], ["", 'q"t'], ["b\\s", "(1)"], [1, nil], nil].map { |k| Rowstile.key_text(k) }
    assert_equal ["7", "7", "(1,2)", '("a b","x,y")', '("","q""t")', '("b\\\\s","(1)")', "(1,)", nil], shown
    assert_equal ["not found", "app.x not found", "row 7 not found"],
                 [Rowstile::NotFound.new, Rowstile::NotFound.new("app.x"), Rowstile::NotFound.new(nil, 7)].map(&:message)
    refused = Rowstile.verdict("app.members", "delete", [1, 2], [], "service 3")
    assert_equal ["permission denied: service 3 may not delete row (1,2) of app.members", []], [refused.message, refused.why]
    assert_equal "the app's database connection can't be used with rowstile: a; b",
                 Rowstile::ConnectionProblem.new(%w[a b]).message
    assert_equal "#<Rowstile::Principal service:3>", Rowstile::Principal.of(["service", 3]).inspect
    assert_equal 1, [Rowstile::Principal.of(1), Rowstile::Principal.of("1")].uniq.size
    assert_not_equal Rowstile::Principal.of(1), "1"
    assert_equal [nil, nil], Rowstile.act_as_args(["service", nil]) # a type and no id: nobody
  end

  # the gem without Rails: no Railtie, the rest as it is
  test "the gem loads without Rails" do
    code = 'require "rowstile"; print [defined?(Rails), defined?(Rowstile::Railtie), Rowstile::Principal.of(3).to_s].inspect'
    said, status = Open3.capture2e("ruby", "-e", code, chdir: File.expand_path("..", __dir__))
    assert status.success?, said
    assert_equal "[nil, nil, \"3\"]", said.lines.last
  end

  # the Minitest helpers say what was expected
  test "the helpers say what was expected" do
    Rowstile.acting_as(3) do
      wrong = assert_raises(Minitest::Assertion) do
        assert_refused(command: "delete") { Note.find(1).update!(body: "x") }
      end
      assert_includes wrong.message, "expected the delete rule to refuse it, but: update"
      none = assert_raises(Minitest::Assertion) { assert_refused { Note.find(4).update!(body: "fine") } }
      assert_includes none.message, "expected a refusal"
      refused = assert_refused(table: "app.notes") do # the driver's error for an insert: a refusal too
        Note.create!(project_id: 3, author_id: 3, body: "x")
      end
      assert_equal "insert", refused.command
    end
    as_user(2) { assert_not_found { Note.find(1) } }
  end

  # a dump of a rowstile database is never loaded: db:migrate and db:prepare make an empty one from its migrations,
  # and loading it any other way says why it can't; another dump loads as Rails loads it
  test "the dump of a rowstile database isn't loaded" do
    config = ActiveRecord::Base.connection_db_config
    error = assert_raises(Rowstile::SchemaLoadRefused) do
      ActiveRecord::Tasks::DatabaseTasks.load_schema(config, :sql, File.expand_path("../db/structure.sql", __dir__))
    end
    assert_includes error.message, "make it with its migrations"
    plain = File.join(Dir.tmpdir, "plain-#{Process.pid}.sql")
    File.write(plain, "SELECT 1;\n")
    ActiveRecord::Base.establish_connection(Rows.owner_config)
    ActiveRecord::Tasks::DatabaseTasks.load_schema(ActiveRecord::Base.connection_db_config, :sql, plain)
  ensure
    ActiveRecord::Base.establish_connection(config.configuration_hash)
    File.delete(plain) if plain && File.exist?(plain)
  end

  test "db:prepare migrates an empty database, and db:schema:load refuses the dump" do
    db = "#{ActiveRecord::Base.connection_db_config.database}_prepare"
    url = TESTS_OWNER.sub(%r{/conf_tests\z}, "/#{db}")
    Rows.owner { |c| c.exec("DROP DATABASE IF EXISTS #{db} WITH (FORCE)") }
    # the committed dump, where Rails reads it before migrating and writes it after (a copy: this is no check of it)
    dump = File.join(Dir.tmpdir, "structure-#{Process.pid}.sql")
    FileUtils.cp(File.expand_path("../db/structure.sql", __dir__), dump)
    env = { "DATABASE_URL" => url, "RAILS_ENV" => "test", "SCHEMA" => dump }
    said, status = Open3.capture2e(env, "bin/rails", "db:prepare", chdir: File.expand_path("..", __dir__))
    assert status.success?, said
    assert_includes said, "AuthzPolicy: migrated"
    said, status = Open3.capture2e(env, "bin/rails", "db:schema:load", chdir: File.expand_path("..", __dir__))
    assert_not status.success?
    assert_includes said, "is a dump of a database with a rowstile policy"
  ensure
    Rows.owner { |c| c.exec("DROP DATABASE IF EXISTS #{db} WITH (FORCE)") }
    File.delete(dump) if dump && File.exist?(dump)
  end
end

# Rails' default for tests: each in a transaction the test begins (as the app's role, before anyone acts). What the
# app runs in it goes as it would without it: a statement outside a transaction signs in as the code acts for, and
# again when that changes; each transaction the app begins (a savepoint) is one principal's
class TransactionalTest < ActionDispatch::IntegrationTest
  self.use_transactional_tests = true
  setup { Rows.load! }

  test "a test in a transaction signs in its statements" do
    assert_equal [EXPECTED["2"], EXPECTED["1"]], [as_user(2) { Note.order(:id).ids }, as_user(1) { Note.order(:id).ids }]
    assert_equal EXPECTED[nil], Note.order(:id).ids # the code acts for no one now: nobody, after a sign-in
    get "/notes", headers: as("3")
    assert_equal EXPECTED["3"], JSON.parse(response.body)
    as_user(1) { Note.find(1).update!(body: "rolled back") } # undone with the test's transaction
  end

  test "each transaction the app begins in a test's is one principal's" do
    refused = as_user(1) do
      Note.transaction { [Note.order(:id).ids, as_user(2) { assert_raises(RuntimeError) { Note.count } }.message] }
    end
    assert_equal EXPECTED["1"], refused[0]
    assert_includes refused[1], "signed in as user 1 already, and a sign-in lasts the database transaction: user 2's work"
    as_user(2) { assert_refused(command: "insert") { Note.create!(project_id: 1, author_id: 2, body: "x") } } # rolled back
    note = as_user(1) { Note.create!(project_id: 1, author_id: 1, body: "x") } # another principal's, after each
    assert_equal [EXPECTED["2"], note.id], [as_user(2) { Note.order(:id).ids }, as_user(1) { Note.find(note.id).id }]
  end
end
