# frozen_string_literal: true

require "test_helper"
require "puma"
require "puma/server"
require "tmpdir"
require "fileutils"

# The checks that serve the app with Puma (4, 5), type-check the generated names (9), look at the test databases
# (12), start the app (13) and change the policy (14).
class ChecksTest < ActiveSupport::TestCase
  HERE = File.expand_path("..", __dir__)
  ROOT = File.expand_path("../../..", __dir__)
  COMMAND = File.join(ROOT, "core/cli/rowstile_cli.py")

  setup { Rows.load! }

  # the app, served by Puma with this many threads, on a port of its own
  def serve(threads)
    server = Puma::Server.new(Rails.application, nil, { min_threads: 0, max_threads: threads })
    port = server.add_tcp_listener("127.0.0.1", 0).addr[1]
    server.run
    yield port
  ensure
    server&.stop(true)
  end

  def notes(port, user, path = "/notes")
    response = Net::HTTP.get_response(URI("http://127.0.0.1:#{port}#{path}"), as(user))
    JSON.parse(response.body)
  end

  # the app's connection with a pool of this size, for the block
  def with_pool(size)
    config = ActiveRecord::Base.connection_db_config.configuration_hash
    ActiveRecord::Base.establish_connection(config.merge(pool: size))
    yield
  ensure
    ActiveRecord::Base.establish_connection(config)
  end

  # 4: one pooled connection, Ann then Bob: Bob never sees Ann's rows
  test "4: a pooled connection carries no one over" do
    with_pool(1) do
      serve(4) do |port|
        assert_equal EXPECTED["1"], notes(port, "1")
        assert_equal EXPECTED["2"], notes(port, "2")
        assert_equal EXPECTED[nil], notes(port, nil)
        # a transaction that commits (a folder moved where it is): a rollback undoes even a session's settings
        request = Net::HTTP::Patch.new("/folders/2", as("1").merge("content-type" => "application/json"))
        request.body = JSON.generate(parent_id: 1)
        assert_equal "200", Net::HTTP.start("127.0.0.1", port) { |http| http.request(request) }.code
      end
      # each request signed in again, so the answers alone can't tell: the pool's one connection, as the last request
      # left it, in a transaction nobody signs in to, holds no one (a sign-in that outlived its transaction would
      # still be ann's here)
      ActiveRecord::Base.with_connection do |c|
        raw = c.raw_connection
        assert_includes [nil, ""], raw.exec("SELECT current_setting('authz.user_id', true) AS u").first["u"]
        raw.transaction do
          error = assert_raises(PG::Error) { raw.exec("SELECT count(*) FROM app.notes") }
          assert_equal "AZ701", Rowstile.error_code(error) # rowstile help AZ701
        end
      end
    end
  end

  # 5: concurrent requests never mix users (Puma's threads, a pool of five)
  test "5: concurrent requests never mix users" do
    users = ["1", "2", "3", nil] * 10
    serve(8) do |port|
      got = users.map { |user| Thread.new { notes(port, user) } }.map(&:value)
      assert_equal users.map { |user| EXPECTED[user] }, got
    end
  end

  # 9: the generated names type-check, and a wrong permission name doesn't: in the generated client, and in the
  # gem's own calls (Steep, with the client's signatures and the gem's)
  test "9: the generated names type-check" do
    # the committed client is the one the policy makes (rowstile client ruby POLICY prints it, and writes nothing)
    { "ruby" => "app/lib/authz.rb", "rbs" => "sig/authz.rbs" }.each do |lang, path|
      made, status = Open3.capture2("python3", COMMAND, "client", lang, "db/policy.authz", chdir: HERE)
      assert status.success?
      assert_equal File.read(File.join(HERE, path)), made, "#{path} is out of date: run rowstile client"
    end
    Dir.mktmpdir do |dir|
      checks = {
        "good" => "Authz.queries.can(\"note\", 1, \"edit\")\nAuthz.queries.can(Authz::Note::TYPE, 1, Authz::Note::VIEW)\n" \
                  "Authz.queries.perms_of(\"project\", [1, 2])\n",
        "client_perm" => "Authz::Note::EDT\n",
        "sdk_perm" => "Authz.queries.can(\"note\", 1, \"edt\")\n",
        "sdk_type" => "Authz.queries.can(\"nte\", 1, \"edit\")\n",
      }
      checks.each { |name, code| File.write(File.join(dir, "#{name}.rb"), code) }
      # (Steep reads the paths from the Steepfile's folder)
      sigs = ["#{HERE}/sig", "#{ROOT}/sdk/ruby/sig", "#{ROOT}/sdk/ruby/steep"].map do |path|
        Pathname(path).relative_path_from(dir).to_s
      end
      File.write(File.join(dir, "Steepfile"), <<~RUBY)
        target :app do
          signature #{sigs.map(&:inspect).join(", ")}
          check "."
          library "json"
          configure_code_diagnostics(Steep::Diagnostic::Ruby.strict)
        end
      RUBY
      said, = Open3.capture2e("bundle", "exec", "steep", "check", "--steepfile", File.join(dir, "Steepfile"), chdir: dir)
      flagged = checks.keys.select { |name| said.include?("#{name}.rb:") }
      assert_equal %w[client_perm sdk_perm sdk_type], flagged, said
      assert_includes said, "EDT"
      assert_includes said, '"edt"'
      assert_includes said, '"nte"'
    end
  end

  # 12: the framework's test database has the policy: each worker on its own copy of the migrated one
  test "12: a test database per worker has the policy" do
    copy = ActiveRecord::Base.connection_db_config.database
    assert_match(/\Aconf_tests_\d+\z/, copy)
    assert_equal "conf_app", ActiveRecord::Base.with_connection { |c| c.select_value("SELECT current_user") }
    assert_equal PROJECTS["2"], Rowstile.acting_as(2) { Project.order(:id).pluck(:id) } # under row-level security
    count = ->(db) { PG.connect(TESTS_OWNER, dbname: db).then { |c| c.exec("SELECT count(*) FROM app.users").getvalue(0, 0).tap { c.close } } }
    assert_equal ["0", "3"], [count.("conf_tests"), count.(copy)] # the original is left as it was migrated
    worker = Integer(copy[/\d+\z/])
    assert_equal copy, Rowstile::Testing.database_per_worker(TESTS_OWNER, worker) # copied again: as migrated
    assert_equal "0", count.(copy)
    Rows.load!
    error = assert_raises(ArgumentError) { Rowstile::Testing.database_per_worker("postgresql://conf_owner:owner@localhost") }
    assert_includes error.message, "a database to copy"
  end

  # 12: ... and a copy is refused, saying why, while something is connected to the original
  test "12: a database per worker says why it can't copy" do
    held = "#{ActiveRecord::Base.connection_db_config.database}_held"
    Rows.owner { |c| c.exec("DROP DATABASE IF EXISTS #{held} WITH (FORCE)"); c.exec("CREATE DATABASE #{held}") }
    url = TESTS_OWNER.sub(%r{/conf_tests\z}, "/#{held}")
    holder = PG.connect(url)
    error = assert_raises(RuntimeError) { Rowstile::Testing.database_per_worker(url, 9) }
    assert_includes error.message, "can't be copied while anything is connected to it"
  ensure
    holder&.close
    Rows.owner { |c| c.exec("DROP DATABASE IF EXISTS #{held} WITH (FORCE)") }
  end

  class OwnerRecord < ActiveRecord::Base
    self.abstract_class = true
  end

  # 13: the app refuses to start on a connection that skips row-level security (here, the owner's)
  test "13: refuses a connection that skips row-level security" do
    config = ActiveRecord::Base.connection_db_config.configuration_hash
    OwnerRecord.establish_connection(Rows.owner_config)
    error = assert_raises(Rowstile::ConnectionProblem) { Rowstile.check_connection!(OwnerRecord) }
    assert_includes error.message, "an owner skips row-level security"
    assert_includes error.problems.join, "owner"
    assert_nil Rowstile.check_connection! # the app's role, under row-level security
    Rails.application.load_server # the server blocks, as config.ru runs them: rowstile's checks the app's role
    OwnerRecord.remove_connection
    # config.rowstile.check_connection = false leaves the check out
    Rails.application.config.rowstile.check_connection = false
    ActiveRecord::Base.establish_connection(Rows.owner_config)
    Rails.application.load_server
  ensure
    Rails.application.config.rowstile.check_connection = true
    ActiveRecord::Base.establish_connection(config)
  end

  # 13, as it happens: `rails server` doesn't start on the owner's connection
  test "13: the app does not start on the owner's connection" do
    env = { "DATABASE_URL" => OWNER, "RAILS_ENV" => "test" }
    said, status = Open3.capture2e(env, "timeout", "120", "bin/rails", "server", "-p", "0", "-P",
                                   File.join(Dir.tmpdir, "rowstile-server-#{Process.pid}.pid"), chdir: HERE)
    assert_equal 1, status.exitstatus, said
    assert_includes said, "an owner skips row-level security"
  end

  # 14: after a policy change and a new migration, the app works with the new generated names. On a copy of the
  # migrated test database
  test "14: a policy change ships as the next migration" do
    db = "#{ActiveRecord::Base.connection_db_config.database}_14"
    Rows.owner do |c|
      c.exec("DROP DATABASE IF EXISTS #{db} WITH (FORCE)")
      c.exec("CREATE DATABASE #{db} TEMPLATE conf_tests")
    end
    Dir.mktmpdir do |dir|
      work = File.join(dir, "app")
      FileUtils.mkdir_p(work)
      Dir.children(HERE).reject { |f| %w[vendor tmp log].include?(f) }.each { |f| FileUtils.cp_r(File.join(HERE, f), work) }
      policy = File.join(work, "db/policy.authz")
      File.write(policy, File.read(policy).sub("  can read = recipient\n", "  can read = recipient\n  can reply = recipient\n"))
      message = PG.connect(TESTS_OWNER, dbname: db).then do |c| # ann sends bo a message
        c.exec("INSERT INTO app.users VALUES (1, 'ann'), (2, 'bo')")
        c.exec("INSERT INTO app.inbox (sender_id, recipient_id, body) VALUES (1, 2, 'hi') RETURNING id").getvalue(0, 0)
      ensure
        c.close
      end
      run = lambda do |env, *command|
        said, status = Open3.capture2e(env, *command, chdir: work)
        assert status.success?, said
        said
      end
      run.({}, "python3", COMMAND, "migrate")
      run.({ "DATABASE_URL" => TESTS_OWNER.sub(%r{/conf_tests\z}, "/#{db}") }, "bin/rails", "db:migrate")
      run.({}, "python3", COMMAND, "client")
      # the app's code, with the client the policy now makes: it names reply, and the database answers it
      script = File.join(work, "said.rb")
      File.write(script, <<~RUBY)
        said = [2, 1].map do |user| # bo, to whom it is sent, may reply; ann, who sent it, may not even read it
          Rowstile.acting_as(user) { [Authz.queries.can("message", #{message}, Authz::Message::REPLY), Authz.queries.can("message", #{message}, "read")] }
        end
        puts JSON.generate(said)
      RUBY
      said = run.({ "DATABASE_URL" => APP.sub(%r{/conf_tests\z}, "/#{db}") }, "bin/rails", "runner", script)
      assert_equal [[true, true], [false, false]], JSON.parse(said.lines.last)
    end
  ensure
    Rows.owner { |c| c.exec("DROP DATABASE IF EXISTS #{db} WITH (FORCE)") }
  end
end
