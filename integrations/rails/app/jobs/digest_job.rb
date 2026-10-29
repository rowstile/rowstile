# frozen_string_literal: true

# A background job: it signs in as service 1, whatever request enqueued it.
class DigestJob < ApplicationJob
  include Rowstile::Job
  acts_for ["service", 1]

  def perform
    [Project.count, Rowstile.current]
  end
end
