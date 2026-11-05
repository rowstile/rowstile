// An admin views the app as someone of their workspace: the session remembers whom, and every read signs in as
// them, read-only (db.ts, reading). Whether the admin may is the policy's (impersonate), asked here first so the
// page can say no; authz.view_as asks it again on every read.
import { route } from "@rowstile/next";
import { db, requestUser } from "@/db.ts";
import { body, noContent } from "@/http.ts";
import { setSession } from "@/session.ts";

export const POST = route(async (req: Request) => {
  const { user } = await body<{ user: string | null }>(req);
  const me = await requestUser();
  if (!me) return Response.json({ title: "sign in first" }, { status: 401 });
  if (user && !(await db.$authz.can("user", user, "impersonate")))
    return Response.json({ title: "you may not view the app as them" }, { status: 403 });
  await setSession(user ? { user: me, viewAs: user } : { user: me });
  return noContent();
});
