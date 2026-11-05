// One ticket: its comments (an internal note only for those who work it: the database leaves the others out),
// what the user may do on it (authz.perms, for the buttons), and changes to it.
import { route } from "@rowstile/next";
import { inTx } from "@/db.ts";
import { body } from "@/http.ts";

type Params = { params: Promise<{ id: string }> };

export const GET = route(async (_req: Request, { params }: Params) => {
  const { id } = await params;
  const found = await inTx(async (tx) => {
    const ticket = await tx.ticket.findUniqueOrThrow({
      where: { id },
      select: {
        id: true, workspaceId: true, subject: true, status: true, teamId: true, assigneeId: true, requesterId: true,
        requester: { select: { name: true } },
        comments: {
          select: { id: true, body: true, internal: true, createdAt: true, author: { select: { name: true } } },
          orderBy: { createdAt: "asc" },
        },
      },
    });
    const [{ perms }] = await tx.$queryRaw<{ perms: string[] }[]>`SELECT authz.perms('ticket', ${id}::text) AS perms`;
    return { ...ticket, perms };
  });
  return Response.json(found);
});

// status, subject, team or assignee: which of them the user may change, and to what, is the policy's
export const PATCH = route(async (req: Request, { params }: Params) => {
  const { id } = await params;
  const data = await body<{ status?: string; subject?: string; teamId?: string | null; assigneeId?: string | null }>(req);
  await inTx((tx) => tx.ticket.update({ where: { id }, data, select: { id: true } }));
  return Response.json({ id });
});
