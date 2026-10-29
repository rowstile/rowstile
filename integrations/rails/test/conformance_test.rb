# frozen_string_literal: true

require "test_helper"

# The conformance suite (integrations/README.md): the same checks for every stack. This is Rails 8, Active Record on
# pg, Puma. test.sh does check 11 (a fresh database: migrate, the policy's tests, then Rails' own diff shows no
# change) before these run.
class ConformanceTest < ActionDispatch::IntegrationTest
  setup { Rows.load! }

  def json = JSON.parse(response.body)

  # 1, 2: a list shows only the user's rows; signed out on purpose, only what anyone may see
  test "1, 2: lists show what each may see" do
    EXPECTED.each do |user, notes|
      get "/notes", headers: as(user)
      assert_equal notes, json, user
    end
    get "/projects"
    assert_equal [3], json
  end

  # 3: not signed in at all: the strict sign-in error, naming act_as
  test "3: not signed in is an error that says how" do
    Rows.app do |conn|
      conn.transaction do
        error = assert_raises(PG::Error) { conn.exec("SELECT count(*) FROM app.notes") }
        assert_equal "28000", Rowstile.sqlstate(error)
        assert_includes error.result.error_field(PG::PG_DIAG_MESSAGE_HINT), "act_as"
        assert_equal "AZ701", Rowstile.error_code(error) # rowstile help AZ701
        assert Rowstile.not_signed_in?(error)
      end
    end
  end

  # 6: a refused insert: 403, with the problem body naming the rule
  test "6: a refused insert says which rule" do
    post "/notes", params: { project_id: 3, body: "hi" }, headers: as("2"), as: :json
    assert_equal 403, response.status, response.body
    assert_equal "application/problem+json", response.media_type
    assert_equal ["app.notes", "insert", "AZ709"], json.values_at("table", "command", "code") # rowstile help AZ709
    assert_includes json["detail"], "user 2 may not insert this row into app.notes"
    assert json["why"].any? { |line| line.include?("project.edit") }, json["why"]
  end

  # 7: an update of a hidden row: 404; of a visible row the user may not edit: 403, with the reason
  test "7: hidden is 404 and not allowed is 403" do
    patch "/notes/1", params: { body: "x" }, headers: as("2"), as: :json
    assert_equal 404, response.status, response.body
    assert_equal({ "type" => "https://rowstile.dev/problems/not-found", "title" => "Not Found", "status" => 404,
                   "detail" => "app.notes 1 not found" }, json)
    patch "/notes/1", params: { body: "x" }, headers: as("3"), as: :json
    assert_equal [403, "update"], [response.status, json["command"]], response.body
    assert json["why"].any? { |line| line.include?("edit") }, json
    # worded as the database words a refused insert: who, the command, the row, the table
    assert_equal "permission denied: user 3 may not update row 1 of app.notes", json["detail"]
    patch "/notes/4", params: { body: "better idea" }, headers: as("3"), as: :json
    assert_equal 200, response.status, response.body
    delete "/notes/2", headers: as("1")
    assert_equal 404, response.status, response.body
    delete "/notes/1", headers: as("3")
    assert_equal [403, "delete"], [response.status, json["command"]], response.body
    assert_equal "permission denied: user 3 may not delete row 1 of app.notes", json["detail"]
    assert_not_empty json["why"]
  end

  # 7: ... and the gem's own 404: cy's note in ann's project, which ann reads and which is in bo's project by the
  # time her update reaches the database. The app found the row: the 404 is the database's answer (explain_rule)
  test "7: a row hidden before the update is 404" do
    moved = []
    meanwhile = ->(_note) { moved << Rows.owner { |c| c.exec("UPDATE app.notes SET project_id = 2 WHERE id = 4").cmd_tuples } }
    Note.set_callback(:update, :before, meanwhile)
    begin
      patch "/notes/4", params: { body: "x" }, headers: as("1"), as: :json
    ensure
      Note.skip_callback(:update, :before, meanwhile)
    end
    assert_equal [1], moved
    assert_equal "application/problem+json", response.media_type
    assert_equal({ "type" => "https://rowstile.dev/problems/not-found", "title" => "Not Found", "status" => 404,
                   "detail" => "app.notes 4 not found" }, json)
  end

  # 8: an insert read back works when the select rule allows it, and is explained when not
  test "8: insert, then read back" do
    post "/notes", params: { project_id: 1, body: "new" }, headers: as("1"), as: :json
    assert_equal 201, response.status, response.body
    assert_operator json["id"], :>, 100
    post "/inbox", params: { recipient_id: 2, body: "hi bo" }, headers: as("1"), as: :json
    assert_equal [403, "select"], [response.status, json["command"]], response.body
    assert_includes json["detail"], "may not see the row as written"
    post "/inbox/quietly", params: { recipient_id: 2, body: "hi bo" }, headers: as("1"), as: :json
    assert_equal 202, response.status, response.body
  end

  # 16: a call the database turns down that is no refusal answers as its code's page says: what it names isn't there
  # (AZ708) 404, a missing or wrong argument (AZ710) 400, with the database's words
  test "16: not there is 404 and a wrong argument 400" do
    key = Rows.owner do |c| # an API key of ann's, in one transaction
      c.transaction do
        c.exec("SELECT authz.act_as('user', '1')")
        c.exec("SELECT authz.create_api_key('ci')")
        c.exec("SELECT max(id) AS id FROM authz.api_keys WHERE user_id = '1'").first.fetch("id")
      end
    end
    get "/projects/page", params: { limit: 1 }, headers: as("1")
    assert_equal [200, ["1"]], [response.status, json], response.body
    { { limit: -1 } => "the page size must not be negative (got -1)",
      { limit: 1, after: "x" } => "the page cursor 'x' is not a project id" }.each do |query, detail|
      get "/projects/page", params: query, headers: as("1")
      assert_equal "application/problem+json", response.media_type
      assert_equal problem("bad-argument", "Bad Request", 400, detail, "AZ710"), json
      assert_equal 400, response.status
    end
    delete "/keys/#{key}", headers: as("2") # bo's key it isn't
    others = [response.status, json]
    delete "/keys/#{key}", headers: as("1")
    assert_equal 204, response.status, response.body
    delete "/keys/#{key}", headers: as("1") # revoked: there is none now
    again = [response.status, json]
    # no refusal: for this user the key isn't there (bo's own keys don't hold it; ann's no longer do)
    [others, again].each do |status, body|
      assert_equal problem("not-found", "Not Found", 404, "no API key #{key} of yours", "AZ708"), body
      assert_equal 404, status
    end
  end

  # 16: and the other codes the runtime raises, each as its page says: a login refused or a call that needs someone
  # signed in 401, a move inside itself 409, a refusal by the database's own code 403; a share the policy doesn't
  # declare, a name not in the policy and who is signed in changed by hand are the app's mistakes, which stay
  # errors (a 500)
  test "16: each code answers as its page says" do
    read_only = Rows.owner do |c| # a key of ann's that may only read
      c.transaction do
        c.exec("SELECT authz.act_as('user', '1')")
        c.exec("SELECT authz.create_api_key('ro', 'read') AS key").first.fetch("key")
      end
    end
    answers = {}
    post "/keys", params: { name: "k" }, as: :json
    answers[:nobody] = response
    post "/projects/1/requests", params: { relation: "member", reason: "the review" }, as: :json
    answers[:asks] = response
    post "/keys", params: { name: "k" }, headers: as("1").merge("x-api-key" => "ak_nope"), as: :json
    answers[:bad_key] = response
    post "/keys", params: { name: "k" }, headers: as("1").merge("x-api-key" => read_only), as: :json
    answers[:scoped] = response
    patch "/folders/1", params: { parent_id: 2 }, headers: as("1"), as: :json
    answers[:inside] = response
    { nobody: problem("not-signed-in", "Unauthorized", 401, "sign in to create an API key", "AZ714"),
      asks: problem("not-signed-in", "Unauthorized", 401, "sign in first", "AZ714"),
      bad_key: problem("not-signed-in", "Unauthorized", 401, "invalid API key", "AZ703"),
      inside: problem("conflict", "Conflict", 409, "folder 1 cannot be moved inside itself", "AZ713") }.each do |k, body|
      assert_equal "application/problem+json", answers[k].media_type, k
      assert_equal body, JSON.parse(answers[k].body), k
      assert_equal body["status"], answers[k].status, k
    end
    post "/keys", params: { name: "k" }, headers: as("1"), as: :json
    assert_equal 201, response.status, response.body
    assert json["key"].start_with?("ak_"), response.body
    patch "/folders/2", params: { parent_id: 1 }, headers: as("1"), as: :json
    assert_equal 200, response.status, response.body
    # refusals, by the database's own code: 403, naming no rule
    get "/projects/1/shares", headers: as("2")
    answers[:not_shared] = response
    [[:scoped, "this session is read-only", "AZ704"], [:not_shared, "you cannot see the shares of project 1", "AZ705"]]
      .each do |k, detail, code|
      got = JSON.parse(answers[k].body)
      assert_equal [403, "https://rowstile.dev/problems/refused", code], [answers[k].status, got["type"], got["code"]]
      assert got["detail"].start_with?(detail), got
      assert_nil got["table"]
      assert_nil got["command"]
    end
    # a call that is for users, made by a service (rowstile help AZ715): a refusal too, 403
    post "/keys", params: { name: "mine" }, headers: { "x-service" => "1" }, as: :json
    assert_equal "application/problem+json", response.media_type
    assert_equal({ "type" => "https://rowstile.dev/problems/refused", "title" => "Forbidden", "status" => 403,
                   "detail" => "authz.create_api_key for oneself is for users, not services (service 1 is signed in)",
                   "table" => nil, "command" => nil, "why" => [], "code" => "AZ715" }, json)
    assert_equal 403, response.status
    # the app's mistakes: the database's own error, not a problem
    said = [
      -> { post "/projects/1/requests", params: { relation: "member", reason: "the review" }, headers: as("2"), as: :json },
      -> { post "/keys", params: { name: "k", principal_type: "service", principal_id: "1" }, headers: as("1"), as: :json },
      -> { get "/notes/as/2", headers: as("1") },
    ].map do |call|
      error = assert_raises(ActiveRecord::StatementInvalid) { call.() }
      [Rowstile.error_code(error), Rowstile.sqlstate(error), error.message]
    end
    assert_equal [["AZ706", "P0001"], ["AZ707", "P0001"], ["AZ702", "28000"]], said.map { |c, s, _| [c, s] }
    ["the policy does not allow sharing project.member with a user",
     "the policy gives service no manage_keys permission, so nobody manages its keys",
     "who is signed in was changed after signing in"].zip(said) { |words, (_, _, message)| assert_includes message, words }
  end

  # 10: a background job signs in as a service principal
  test "10: a job acts as its service" do
    count, who = Rowstile.acting_as(3) { DigestJob.perform_now } # whatever started it
    assert_equal Rowstile::Principal.new(type: "service", id: "1"), who
    assert_equal 2, count # project 1 (it is added to) and the public one
  end

  # ... and only when the code names it: an id is a user's, whatever it holds (ids come from outside)
  test "10: an id with a colon is a user's, not a service" do
    assert_equal Rowstile::Principal.new(type: "user", id: "service:1"), Rowstile::Principal.of("service:1")
    assert_equal Rowstile::Principal.new(type: "service", id: "1"), Rowstile::Principal.of(["service", 1])
    # what to_s wrote, read back, for text the app wrote itself (a job's argument): every principal as itself
    users = ["service:1", "nobody", "google-oauth2:117", "user:5", "a:b", ":", "(1,a:b)", "(1,2)", "", "42"]
    every = users.map { |u| Rowstile::Principal.of(u) } + [Rowstile::NOBODY, Rowstile::Principal.of(["service", 1])]
    every += [Rowstile::Principal.new(type: "service", id: "3:4"), Rowstile::Principal.new(type: "service", id: "(1,2)")]
    assert_equal every, every.map { |p| Rowstile::Principal.parse(p.to_s) }
    assert_equal ["user:service:1", "user:nobody", "42", "service:1", "nobody"],
                 [*%w[service:1 nobody 42].map { |u| Rowstile::Principal.of(u).to_s },
                  Rowstile::Principal.of(["service", 1]).to_s, Rowstile::NOBODY.to_s]
  end
end
