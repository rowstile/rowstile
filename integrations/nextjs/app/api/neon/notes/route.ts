// Neon's serverless driver on the Node.js runtime: the server's one pool, over WebSockets (src/neon.ts)
import { route } from "@rowstile/next";
import { neon } from "@/neon";

export const GET = route(async () => {
  const { rows } = await neon.query("SELECT id FROM app.notes ORDER BY id");
  return Response.json(rows.map((r) => r.id));
});

// an insert the rules may refuse: 403 with the rule and why
export const POST = route(async (req: Request) => {
  const { project_id, body } = (await req.json()) as { project_id: number; body: string };
  await neon.query("INSERT INTO app.notes (project_id, author_id, body) VALUES ($1, authz.uid()::integer, $2)", [project_id, body]);
  return new Response(null, { status: 201 });
});
