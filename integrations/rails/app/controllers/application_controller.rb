# frozen_string_literal: true

class ApplicationController < ActionController::API
  private

  # The user the request acts for (rowstile set it from SessionUser), as the tables' key.
  def signed_in
    Rowstile.current&.id.to_i
  end

  # A statement with $1, $2... and its values, on the app's connection: signed in as the request's user.
  def sql_value(sql, *values)
    ApplicationRecord.with_connection { |c| c.select_value(sql, "app", values) }
  end
end
