// A custom role of the workspace (Escalations, Billing specialist): its admins make them, and the role's id is
// what a ticket shares as role:<id>
import { route } from "@rowstile/next";
import { inTx } from "@/db.ts";
import { body } from "@/http.ts";

export const POST = route(async (req: Request) => {
  const { workspaceId, name, perms } = await body<{ workspaceId: string; name: string; perms: string[] }>(req);
  const [{ id }] = await inTx((tx) => tx.$queryRaw<{ id: number }[]>`
    SELECT authz.create_role('workspace', ${workspaceId}::text, 'ticket', ${name}, ${perms}::text[]) AS id`);
  return Response.json({ id: Number(id) }, { status: 201 });
});
