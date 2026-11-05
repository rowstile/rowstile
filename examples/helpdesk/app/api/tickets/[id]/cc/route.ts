// Copying someone in: a share of the relation cc. Who may give it, and to whom (someone of the ticket's own
// workspace), is the policy's: anyone else gets a 403.
import { route } from "@rowstile/next";
import { db } from "@/db.ts";
import { body, noContent } from "@/http.ts";

type Params = { params: Promise<{ id: string }> };

export const POST = route(async (req: Request, { params }: Params) => {
  const { user } = await body<{ user: string }>(req);
  await db.$authz.share("ticket", (await params).id, "cc", "user", user);
  return noContent();
});

// and taking them off it: an unshare, which only someone who may share it may make
export const DELETE = route(async (req: Request, { params }: Params) => {
  const { user } = await body<{ user: string }>(req);
  await db.$authz.unshare("ticket", (await params).id, "cc", "user", user);
  return noContent();
});
