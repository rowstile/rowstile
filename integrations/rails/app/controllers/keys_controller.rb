# frozen_string_literal: true

class KeysController < ApplicationController
  # an API key, for the user or a principal whose keys they manage; a request that brings a key (x-api-key) signs
  # in with it first, in the same transaction: the database says who may make which
  def create
    key = ApplicationRecord.transaction do
      given = request.headers["x-api-key"]
      sql_value("SELECT authz.login_key($1)", given) if given
      sql_value("SELECT authz.create_api_key($1, '', NULL, CAST($2 AS text), CAST($3 AS text))",
                params[:name], params[:principal_type], params[:principal_id])
    end
    render json: { key: key }, status: :created
  end

  # one of the user's API keys: someone else's, or one that isn't there, is 404
  def destroy
    sql_value("SELECT 1 FROM authz.revoke_api_key($1)", Integer(params[:id]))
    head :no_content
  end
end
