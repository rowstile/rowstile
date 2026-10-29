# frozen_string_literal: true

Rails.application.routes.draw do
  get "projects" => "projects#index"
  get "projects/editable" => "projects#editable"
  get "projects/buttons" => "projects#buttons"
  get "projects/page" => "projects#page"
  get "projects/:id/shares" => "projects#shares"
  post "projects/:id/requests" => "projects#ask"
  post "keys" => "keys#create"
  delete "keys/:id" => "keys#destroy"
  get "notes" => "notes#index"
  get "notes/as/:user_id" => "notes#as"
  post "notes" => "notes#create"
  patch "notes/:id" => "notes#update"
  delete "notes/:id" => "notes#destroy"
  post "inbox" => "inbox#create"
  post "inbox/quietly" => "inbox#quietly"
  patch "folders/:id" => "folders#update"
end
