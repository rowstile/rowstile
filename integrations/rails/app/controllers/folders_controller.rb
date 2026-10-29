# frozen_string_literal: true

class FoldersController < ApplicationController
  def update
    folder = Folder.find(params[:id])
    folder.update!(parent_id: params[:parent_id]) # inside one of its own subfolders: 409, the database's words
    render json: { id: folder.id }
  end
end
