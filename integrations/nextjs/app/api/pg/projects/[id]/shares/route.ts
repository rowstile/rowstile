// The sharing dialog on pg: who may list, share and unshare is the database's to say, and a refusal is 403
import { route } from "@rowstile/next";
import { sql } from "@/pg";

type Params = { params: Promise<{ id: string }> };

export const GET = route(async (_req: Request, { params }: Params) => {
  const shares = await sql.listShares("project", Number((await params).id));
  return Response.json(shares.map((s) => ({ relation: s.relation, user: s.subject_id })));
});

export const POST = route(async (req: Request, { params }: Params) => {
  const { user } = (await req.json()) as { user: number };
  await sql.share("project", Number((await params).id), "viewer", "user", user);
  return new Response(null, { status: 204 });
});

export const DELETE = route(async (req: Request, { params }: Params) => {
  const { user } = (await req.json()) as { user: number };
  await sql.unshare("project", Number((await params).id), "viewer", "user", user);
  return new Response(null, { status: 204 });
});
