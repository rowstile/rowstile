// A person's page. The agents' notes on a customer come from the masked view, hd.users_visible: null for anyone
// the policy doesn't let read them (the customer included), and the table itself refuses the column to everyone.
import { route } from "@rowstile/next";
import { inTx } from "@/db.ts";
import { body } from "@/http.ts";

type Params = { params: Promise<{ id: string }> };
interface Person { id: string; name: string; email: string; kind: string; notes: string | null }

export const GET = route(async (_req: Request, { params }: Params) => {
  const { id } = await params;
  const [person] = await inTx((tx) => tx.$queryRaw<Person[]>`
    SELECT id::text, name, email, kind, notes FROM hd.users_visible WHERE id = ${id}::uuid`);
  return person ? Response.json(person) : Response.json({ title: "not found" }, { status: 404 });
});

// a name, or the agents' notes: only those fields are written, whatever else the body holds (not the address: it
// is how the email intake knows who sent a mail, and the policy lets only an admin change it)
export const PATCH = route(async (req: Request, { params }: Params) => {
  const { id } = await params;
  const { name, notes } = await body<{ name?: string; notes?: string }>(req);
  await inTx((tx) => tx.user.update({ where: { id }, data: { name, notes }, select: { id: true } }));
  return Response.json({ id });
});
