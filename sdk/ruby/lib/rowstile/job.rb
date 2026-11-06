# frozen_string_literal: true

module Rowstile
  # Active Job: the job acts for the principal it names, whatever request enqueued it.
  #
  #   class DigestJob < ApplicationJob
  #     include Rowstile::Job
  #     acts_for ["service", 1]
  #   end
  #
  # A job that includes it and names no one acts for nobody (only what `anyone` may see). Its arguments are read as
  # its principal too: a record given to perform_later is found again when the job runs (Note.find), which Active
  # Job does before the perform callbacks, so the whole of perform_now acts for it.
  module Job
    def self.included(job)
      job.extend(ClassMethods)
      job.class_attribute :rowstile_principal, instance_writer: false, default: NOBODY
    end

    def perform_now
      Rowstile.acting_as(rowstile_principal) { super }
    end

    # acts_for(who): who the job acts for (42, ["service", 3], nil for nobody)
    module ClassMethods
      def acts_for(who)
        self.rowstile_principal = Principal.of(who)
      end
    end
  end
end
