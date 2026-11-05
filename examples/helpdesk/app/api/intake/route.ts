// The email intake: a mail becomes a ticket (or a reply on one), its sender a customer if they are new. It signs
// in with the integration's key (Authorization: Bearer ...), limited to the scope intake: whatever the mail says,
// the key can do nothing else, and only in its own workspace.
import { route } from "@rowstile/next";
import { db } from "@/db.ts";
import { body } from "@/http.ts";

interface Mail { workspaceId: string; from: string; name: string; subject: string; body: string; ticketId?: string }

export const POST = route(async (req: Request) => {
  const key = req.headers.get("authorization")?.replace(/^Bearer /, "");
  if (!key) return Response.json({ title: "a key, as Authorization: Bearer" }, { status: 401 });
  const mail = await body<Mail>(req);
  const made = await db.$transaction(async (tx) => {
    const [{ integration }] = await tx.$queryRaw<{ integration: string }[]>`
      SELECT p.principal_id AS integration FROM authz.login_key(${key}) l, authz.principal() p`;
    const known = await tx.user.findFirst({ where: { workspaceId: mail.workspaceId, email: mail.from }, select: { id: true } });
    const sender = known ?? (await tx.user.create({
      data: { workspaceId: mail.workspaceId, kind: "customer", name: mail.name, email: mail.from },
      select: { id: true },
    }));
    const ticket = mail.ticketId
      ? { id: mail.ticketId }
      : await tx.ticket.create({ data: { workspaceId: mail.workspaceId, subject: mail.subject, requesterId: sender.id }, select: { id: true } });
    await tx.comment.create({ data: { ticketId: ticket.id, integrationId: integration, body: mail.body }, select: { id: true } });
    return { ticket: ticket.id, sender: sender.id };
  });
  return Response.json(made, { status: 201 });
});
