# frozen_string_literal: true

class InboxController < ApplicationController
  # reads the new row back (INSERT ... RETURNING id): only the recipient may read it
  def create
    message = Message.create!(sender_id: signed_in, recipient_id: params[:recipient_id], body: params[:body])
    render json: { id: message.id }, status: :created
  end

  # without reading the row back
  def quietly
    Message.insert!({ sender_id: signed_in, recipient_id: params[:recipient_id], body: params[:body] },
                    returning: false)
    render json: {}, status: :accepted
  end
end
