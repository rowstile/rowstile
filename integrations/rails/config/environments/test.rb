# frozen_string_literal: true

Rails.application.configure do
  config.enable_reloading = false
  config.action_dispatch.show_exceptions = :none
  # the test database is migrated, never loaded from db/structure.sql (which holds no grants, nor the policy's own
  # rows): Rails mustn't load it over a migrated one, nor into each worker's (test/test_helper.rb copies it)
  config.active_record.maintain_test_schema = false
  config.active_support.parallelize_test_databases = false
  config.active_job.queue_adapter = :test
end
