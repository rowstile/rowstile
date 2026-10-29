# frozen_string_literal: true

ENV["RAILS_ENV"] ||= "test"
require_relative "../config/environment"
require "rails/test_help"
require "rowstile/testing"
require "net/http"
require "open3"

# The suite's databases: the tables' owner on the migrated test database (test.sh migrates it; each worker gets a
# copy of it), and the app's role on it (DATABASE_URL, which the copy's settings come from)
TESTS_OWNER = ENV.fetch("ROWSTILE_TESTS_URL")
OWNER = ENV.fetch("ROWSTILE_OWNER_URL") # the development database, migrated for check 11
APP = ENV.fetch("ROWSTILE_APP_TESTS_URL") # the app role, on the test database (its host and port)

# The same few rows for every test: ann (1) owns project 1 (cy is a member, service 1 reads it) and the public
# project 3; bo (2) owns project 2. Ann's folder 1 has folder 2 inside it.
module Rows
  ROWS = <<~SQL
    TRUNCATE app.folders, app.inbox, app.notes, app.members, app.project_services, app.projects, app.services,
      app.users CASCADE;
    INSERT INTO app.users VALUES (1, 'ann'), (2, 'bo'), (3, 'cy');
    INSERT INTO app.services VALUES (1, 'digest');
    INSERT INTO app.projects VALUES (1, 1, 'Plans', false), (2, 2, 'Bo''s', false), (3, 1, 'Open', true);
    INSERT INTO app.members VALUES (1, 3);
    INSERT INTO app.project_services VALUES (1, 1);
    INSERT INTO app.notes (id, project_id, author_id, body) VALUES
      (1, 1, 1, 'plan'), (2, 2, 2, 'mine'), (3, 3, 1, 'hello'), (4, 1, 3, 'idea');
    SELECT setval(pg_get_serial_sequence('app.notes', 'id'), 100);
    INSERT INTO app.folders VALUES (1, NULL, 1, 'top'), (2, 1, 1, 'inside');
  SQL

  # The owner's connection to this worker's database (the app's is Active Record's)
  def self.owner(&)
    conn = PG.connect(TESTS_OWNER, dbname: ActiveRecord::Base.connection_db_config.database)
    conn.exec("SET client_min_messages = warning")
    yield conn
  ensure
    conn&.close
  end

  # The app role's own connection to this worker's database, outside Active Record (signed in by nothing)
  def self.app(&)
    conn = PG.connect(APP, dbname: ActiveRecord::Base.connection_db_config.database)
    yield conn
  ensure
    conn&.close
  end

  # Active Record's settings for the owner on this worker's database: straight to Postgres, as the owner always
  # connects (behind a pooler, only the app does)
  def self.owner_config
    { adapter: "postgresql", url: TESTS_OWNER.sub(%r{/conf_tests\z}, "/#{ActiveRecord::Base.connection_db_config.database}") }
  end

  def self.load!
    owner { |conn| conn.exec(ROWS) }
  end
end

class ActiveSupport::TestCase
  include Rowstile::Testing

  # the checks read and write the same rows: no transaction around each test (the tests that write put back what
  # they change), and each worker on a database of its own (check 12)
  self.use_transactional_tests = false
  parallelize(workers: 2, threshold: 1)
  parallelize_setup do |worker|
    Rowstile::Testing.database_per_worker(TESTS_OWNER, worker)
    Rows.load!
  end

  EXPECTED = { "1" => [1, 3, 4], "2" => [2, 3], "3" => [1, 3, 4], nil => [3] }.freeze
  PROJECTS = { "1" => [1, 3], "2" => [2, 3], nil => [3] }.freeze # the projects each may see

  def as(user)
    user ? { "x-user" => user } : {}
  end

  # a problem body, as the gem writes one
  def problem(kind, title, status, detail, code)
    { "type" => "https://rowstile.dev/problems/#{kind}", "title" => title, "status" => status, "detail" => detail,
      "code" => code }
  end
end
