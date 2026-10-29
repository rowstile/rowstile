# frozen_string_literal: true

class NotesController < ApplicationController
  def index
    render json: Note.order(:id).pluck(:id)
  end

  def create
    note = Note.create!(project_id: params[:project_id], author_id: signed_in, body: params[:body])
    render json: { id: note.id }, status: :created
  end

  def update
    note = Note.find(params[:id])     # a row the user can't see: 404
    note.update!(body: params[:body]) # an update the rules refuse: 403, with the reason
    render json: { id: note.id }
  end

  def destroy
    Note.find(params[:id]).destroy!
    head :no_content
  end

  # who is signed in, changed by hand: the database doesn't believe it (the app's bug, a 500)
  def as
    ids = ApplicationRecord.transaction do
      sql_value("SELECT set_config('authz.user_id', $1, true)", params[:user_id])
      Note.order(:id).pluck(:id)
    end
    render json: ids
  end
end
