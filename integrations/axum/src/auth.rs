//! Who a request is. A real app reads its session or token here: a cookie, a bearer token, an API key. The
//! conformance app has no sign-in: its checks name the user in a header, which a real app must never believe. So
//! docs/stacks/axum.md shows the app's state calling `session_user`, and never this file.

use axum::http::request::Parts;
use rowstile::{Error, Principal};

pub fn session_user(request: &Parts) -> Result<Principal, Error> {
    let header = |name: &str| request.headers.get(name).and_then(|v| v.to_str().ok());
    if header("authorization") == Some("Bearer bad") {
        // a token the app refuses: 401
        return Err(Error::unauthorized("bad token"));
    }
    if let Some(service) = header("x-service") {
        // a service's own API calls
        return Ok(Principal::of("service", service));
    }
    Ok(header("x-user").map_or(Principal::Nobody, Principal::user))
}
