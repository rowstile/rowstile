// The edge runtime, through Neon's serverless driver: a pool for each request (src/neon.ts). An app of its own:
// Next refuses `runtime` in an app with "use cache" (edge/next.config.ts)
import { route } from "@rowstile/next";
import { edgeSql } from "@/neon";

export const runtime = "edge";

export const GET = route(async () => {
  const { rows } = await edgeSql().query("SELECT id FROM app.notes ORDER BY id");
  return Response.json(rows.map((r) => r.id));
});

export const POST = route(async (req: Request) => {
  const { project_id, body } = (await req.json()) as { project_id: number; body: string };
  await edgeSql().query("INSERT INTO app.notes (project_id, author_id, body) VALUES ($1, authz.uid()::integer, $2)", [project_id, body]);
  return new Response(null, { status: 201 });
});
