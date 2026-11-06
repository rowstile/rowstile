// The email intake: a mail becomes a ticket (its sender a customer if they are new), or a reply on one. It signs
// in with the integration's key (Authorization: Bearer ...), limited to the scope intake: whatever the mail says,
// the key can do nothing else, and only in its own workspace. The sender is whoever has the mail's address in the
// workspace (hd.users.email, which only an admin may change), in any case. A reply comes from someone who may reply
// on the ticket (its requester, someone copied in): the database is asked as them, and an unknown address makes
// no one. A comment by mail names its sender as its author, and the intake.
import { actingAs } from "@rowstile/client";
import { route } from "@rowstile/next";
import { db, type Tx } from "@/db.ts";
import { body } from "@/http.ts";

interface Mail { workspaceId: string; from: string; name: string; subject: string; body: string; ticketId?: string }

/** fn in a transaction signed in with the key, and the integration it is the key of. */
function withKey<R>(key: string, fn: (tx: Tx, integration: string) => Promise<R>): Promise<R> {
  return db.$transaction(async (tx) => {
    // signing in, then who that is: two statements, so the second reads what the first did
    await tx.$executeRaw`SELECT authz.login_key(${key})`;
    const [{ integration }] = await tx.$queryRaw<{ integration: string }[]>`SELECT principal_id AS integration FROM authz.principal()`;
    return fn(tx, integration);
  });
}

/** The workspace's person with the mail's address, if there is one. */
const sender = (tx: Tx, mail: Mail) =>
  tx.user.findFirst({ where: { workspaceId: mail.workspaceId, email: { equals: mail.from.trim(), mode: "insensitive" } }, select: { id: true } });

export const POST = route(async (req: Request) => {
  const key = req.headers.get("authorization")?.replace(/^Bearer /, "");
  if (!key) return Response.json({ title: "a key, as Authorization: Bearer" }, { status: 401 });
  const mail = await body<Mail>(req);
  const ticketId = mail.ticketId;
  if (ticketId) {
    const from = await withKey(key, (tx) => sender(tx, mail));
    if (!from || !(await actingAs(from.id, () => db.$authz.can("ticket", ticketId, "reply"))))
      return Response.json({ title: "the sender may not reply on this ticket" }, { status: 403 });
    await withKey(key, (tx, integration) =>
      tx.comment.create({ data: { ticketId, authorId: from.id, integrationId: integration, body: mail.body }, select: { id: true } }));
    return Response.json({ ticket: ticketId, sender: from.id }, { status: 201 });
  }
  const made = await withKey(key, async (tx, integration) => {
    const from = (await sender(tx, mail)) ?? (await tx.user.create({
      data: { workspaceId: mail.workspaceId, kind: "customer", name: mail.name, email: mail.from.trim().toLowerCase() },
      select: { id: true },
    }));
    const ticket = await tx.ticket.create({ data: { workspaceId: mail.workspaceId, subject: mail.subject, requesterId: from.id }, select: { id: true } });
    await tx.comment.create({ data: { ticketId: ticket.id, authorId: from.id, integrationId: integration, body: mail.body }, select: { id: true } });
    return { ticket: ticket.id, sender: from.id };
  });
  return Response.json(made, { status: 201 });
});
