# frozen_string_literal: true

class ProjectsController < ApplicationController
  def index
    render json: Project.order(:id).pluck(:id)
  end

  # the projects the user may edit: one set lookup, taking only the policy's names (Authz, the generated client)
  def editable
    render json: Authz.queries.permitted(Project.all, "project", "edit").order(:id).pluck(:id)
  end

  # a list's buttons, in one call
  def buttons
    render json: Authz.queries.perms_of("project", Project.order(:id).pluck(:id))
  end

  # the projects the user may see, a page at a time: the database says when the size or the cursor is wrong
  def page
    listed = ApplicationRecord.with_connection do |c|
      c.select_values("SELECT x FROM authz.list('project', 'view', $1, $2) x", "app",
                      [params[:after], Integer(params.fetch(:limit))])
    end
    render json: listed
  end

  def shares
    listed = ApplicationRecord.with_connection do |c|
      c.select_values("SELECT subject_id FROM authz.list_shares('project', $1)", "app", [params[:id]])
    end
    render json: listed
  end

  # access asked for: the policy shares no relation of a project, so this is the app's mistake (a 500), once the
  # database knows who asks
  def ask
    id = sql_value("SELECT authz.request_access('project', $1, $2, $3)", params[:id], params[:relation], params[:reason])
    render json: { id: id }, status: :created
  end
end
