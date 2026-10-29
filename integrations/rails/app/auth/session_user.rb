# frozen_string_literal: true

# Who a request is. A real app reads its session or token here: a cookie, a bearer token, an API key. The
# conformance app has no sign-in: its checks name the user in a header, which a real app must never believe. So
# docs/stacks/rails.md shows config/application.rb calling SessionUser, and never this file.
module SessionUser
  # The request's signed-in user (nil: nobody), or a service (x-service: a service's own API calls).
  def self.call(request)
    service = request.headers["x-service"]
    return ["service", service] if service

    request.headers["x-user"]
  end
end
