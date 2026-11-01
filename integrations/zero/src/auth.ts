// Who a request is. A real app verifies its tokens (a session's, a JWT): Zero hands the client's `auth` to the
// app's endpoints as `Authorization: Bearer <token>`. The conformance app has no sign-in: its token is the user's id,
// which a real app must never believe, or `key:<secret>`, an API key, which signs in with authz.login_key() in the
// transaction itself.
export type Token = { user: string } | { key: string } | null;

export function tokenOf(headers: Headers): Token {
  const bearer = /^Bearer (.+)$/.exec(headers.get("authorization") ?? "")?.[1];
  if (bearer === undefined) return null;
  return bearer.startsWith("key:") ? { key: bearer.slice(4) } : { user: bearer };
}
