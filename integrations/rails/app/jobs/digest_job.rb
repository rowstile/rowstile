# frozen_string_literal: true

# A background job: it signs in as service 1, whatever request enqueued it, and reads the project it is given (a
# record: Active Job finds it again when the job runs) as service 1 too.
class DigestJob < ApplicationJob
  include Rowstile::Job
  acts_for ["service", 1]

  def perform(project = nil)
    [Project.count, Rowstile.current, project&.name]
  end
end
