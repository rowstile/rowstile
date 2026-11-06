// The tickets the request's user may see, and a new one. No filter and no check here: row-level security gives
// each person their own, and refuses what the policy doesn't allow (route() answers 403 with the reason).
import { route } from "@rowstile/next";
import { inTx, requestUser } from "@/db.ts";
import { body } from "@/http.ts";

export const GET = route(async () => {
  const tickets = await inTx((tx) =>
    tx.ticket.findMany({
      select: {
        id: true, subject: true, status: true, teamId: true, assigneeId: true, requesterId: true, createdAt: true,
        requester: { select: { name: true } },
      },
      orderBy: { createdAt: "desc" },
    }),
  );
  return Response.json(tickets);
});

// A ticket and its first comment, by whoever opens it. One opened for someone else (an agent, for a customer who
// phoned) is the opener's to work, unless it names who works it: else its first comment, theirs, would be refused.
export const POST = route(async (req: Request) => {
  const { workspaceId, subject, body: text, requesterId, teamId, assigneeId } = await body<{
    workspaceId: string; subject: string; body: string; requesterId: string; teamId?: string; assigneeId?: string;
  }>(req);
  const me = await requestUser();
  const assignee = assigneeId ?? (me !== null && me !== requesterId ? me : undefined);
  const ticket = await inTx(async (tx) => {
    const t = await tx.ticket.create({ data: { workspaceId, subject, requesterId, teamId, assigneeId: assignee }, select: { id: true } });
    await tx.comment.create({ data: { ticketId: t.id, authorId: me, body: text }, select: { id: true } });
    return t;
  });
  return Response.json(ticket, { status: 201 });
});
