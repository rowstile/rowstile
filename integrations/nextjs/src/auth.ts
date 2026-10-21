// Who the request is. A real app's auth() reads its session: Auth.js's, or its own cookie or token. The
// conformance app has no sign-in: its checks name the user in a header, which a real app must never believe.
// So docs/stacks/nextjs.md shows src/db.ts calling auth(), and never this file.
import { headers } from "next/headers";

export async function auth(): Promise<{ user?: { id?: string } } | null> {
  const id = (await headers()).get("x-user");
  return id === null ? null : { user: { id } };
}
