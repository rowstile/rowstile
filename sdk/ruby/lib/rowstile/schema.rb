# frozen_string_literal: true

require "active_record"

module Rowstile
  # A dump of a database with a rowstile policy (db/structure.sql) can't make one: it leaves out the grants (Rails
  # dumps with --no-privileges) and the policy's own rows. So such a database is made by its migrations alone. Rails
  # loads the dump into an empty database before migrating it (db:migrate, db:prepare): for a dump of the policy's
  # tables, rowstile has it run every migration instead. Loading one any other way (db:schema:load, db:setup,
  # db:reset, the test database Rails keeps up to date or makes for each worker) raises SchemaLoadRefused, before
  # Rails empties a database to load it (db:test:prepare, which maintain_test_schema runs, and a worker's database).
  class SchemaLoadRefused < StandardError; end

  # Rails' database tasks, with the dumps of a rowstile database left unloaded (Rowstile::SchemaLoadRefused).
  module SchemaLoad
    def load_schema(db_config, format = db_config.schema_format, file = nil)
      path = file || schema_dump_path(db_config, format)
      return super unless SchemaLoad.dump?(path)
      raise SchemaLoad.refused(path) unless @rowstile_migrating
    end

    # a test database made again from the dump (a worker's, parallelize_test_databases): refused before it is emptied
    def reconstruct_from_schema(db_config, file = nil)
      path = file || schema_dump_path(db_config, db_config.schema_format)
      raise SchemaLoad.refused(path) if SchemaLoad.dump?(path)

      super
    end

    # db:test:prepare empties the test database (db:test:purge), then loads the dump into it: the Railtie runs this
    # first, so that a dump of a rowstile database is refused before anything is emptied
    def self.refuse_test_dumps
      ActiveRecord::Base.configurations.configs_for(env_name: "test").each do |db_config|
        format = ENV["SCHEMA_FORMAT"] || db_config.schema_format # (as Rails' db:test:load_schema reads it)
        path = ActiveRecord::Tasks::DatabaseTasks.schema_dump_path(db_config, format)
        raise refused(path) if dump?(path)
      end
    end

    # whether the file at path is a dump of a database with a rowstile policy
    def self.dump?(path)
      !path.nil? && File.exist?(path) && File.read(path).match?(/\bauthz_(gen|int)\./)
    end

    def self.refused(path)
      SchemaLoadRefused.new("rowstile: #{path} is a dump of a database with a rowstile policy, which can't make " \
                            "one (it holds no grants, nor the policy's own rows): make it with its migrations " \
                            "(bin/rails db:migrate, on an empty database). For tests, migrate the test database " \
                            "and copy it for each worker (Rowstile::Testing.database_per_worker), with " \
                            "config.active_record.maintain_test_schema and " \
                            "config.active_support.parallelize_test_databases false")
    end

    private

    # an empty database that db:migrate or db:prepare is about to migrate: from its first migration
    def initialize_database(db_config)
      @rowstile_migrating = true
      super
    ensure
      @rowstile_migrating = false
    end
  end
end

ActiveSupport.on_load(:active_record) { |_| ActiveRecord::Tasks::DatabaseTasks.singleton_class.prepend(Rowstile::SchemaLoad) }
