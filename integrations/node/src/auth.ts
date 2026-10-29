// Who the request is. A real app reads its session: a cookie, a token, Passport's req.user. The conformance app
// has no sign-in: its checks name the user in a header, which a real app must never believe. So
// docs/stacks/node.md shows src/app.ts calling userOf(req), and never this file.
import type { Request } from "express";

export function userOf(req: Request): string | null {
  return req.get("x-user") ?? null;
}
