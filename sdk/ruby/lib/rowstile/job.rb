# frozen_string_literal: true

module Rowstile
  # Active Job: the job acts for the principal it names, whatever request enqueued it.
  #
  #   class DigestJob < ApplicationJob
  #     include Rowstile::Job
  #     acts_for ["service", 1]
  #   end
  #
  # A job that includes it and names no one acts for nobody (only what `anyone` may see).
  module Job
    def self.included(job)
      job.extend(ClassMethods)
      job.class_attribute :rowstile_principal, instance_writer: false, default: NOBODY
      job.around_perform { |performed, block| Rowstile.acting_as(performed.rowstile_principal) { block.call } }
    end

    # acts_for(who): who the job acts for (42, ["service", 3], nil for nobody)
    module ClassMethods
      def acts_for(who)
        self.rowstile_principal = Principal.of(who)
      end
    end
  end
end
