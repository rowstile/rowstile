// Who the request is. A real app reads its session: a cookie, a token, Passport's req.user. The conformance app
// has no sign-in: its checks name the user in a header, which a real app must never believe. An API key signs in
// with authz.login_key(), in the transaction itself.
export const USER = "x-user";
export const KEY = "x-api-key";

export function userOf(headers: Headers): string | null {
  return headers.get(USER);
}

export function keyOf(headers: Headers): string | null {
  return headers.get(KEY);
}
