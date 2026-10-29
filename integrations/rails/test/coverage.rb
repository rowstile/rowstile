# frozen_string_literal: true

# What the checks run of the gem (sdk/ruby/lib), lines and branches, with SimpleCov. Every Ruby process of the
# tests loads this first (RUBYOPT, which test/test_helper.rb passes on: the tests, Rails' two workers, and the
# servers and migrations the checks start), and stores what it ran in CONFORMANCE_COVERAGE. Then test.sh reports
# on all of it (ruby test/coverage.rb --report DIR): each file's lines and branches, and what no check runs; it
# exits 1 below 100%.
require "bundler/setup"
require "simplecov"

module Measured
  SDK = File.expand_path("../../../sdk/ruby", __dir__)

  # each file of the gem, its lines and branches, and those no check ran
  class Report
    def format(result)
      result.files.sort_by(&:filename).each do |file|
        missed = file.missed_lines.map(&:number) + file.missed_branches.map { |b| "#{b.report_line} (#{b.type})" }
        printf("%-40s lines %6.2f%%  branches %6.2f%%  %s\n", file.filename.delete_prefix("#{SDK}/"),
               file.covered_percent(:line), file.covered_percent(:branch), missed.join(", "))
      end
    end
  end

  def self.configure(config)
    config.root SDK
    config.coverage_dir ENV.fetch("CONFORMANCE_COVERAGE")
    config.enable_coverage :branch
    config.cover "lib/**/*.rb"
  end
end

if ARGV.first == "--report"
  ENV["CONFORMANCE_COVERAGE"] = ARGV[1]
  SimpleCov.collate(Dir[File.join(ARGV[1], ".resultset*.json")]) do
    Measured.configure(self)
    formatter Measured::Report
    coverage :line, minimum: 100
    coverage :branch, minimum: 100
  end
else
  SimpleCov.command_name "#{File.basename($PROGRAM_NAME)} #{ARGV.first} #{Process.pid}"
  SimpleCov.start do
    Measured.configure(self)
    merge_subprocesses true
    finalize_merge false
    print_errors false
  end
end
