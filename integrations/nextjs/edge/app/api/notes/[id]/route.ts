import { route } from "@rowstile/next";
import { edgeSql } from "@/neon";

export const runtime = "edge";

type Params = { params: Promise<{ id: string }> };

export const PATCH = route(async (req: Request, { params }: Params) => {
  const id = Number((await params).id);
  const { body } = (await req.json()) as { body: string };
  const sql = edgeSql();
  await sql.transaction(async (c) =>
    sql.expect(await c.query("UPDATE app.notes SET body = $1 WHERE id = $2", [body, id]), "app.notes", "update", id));
  return Response.json({ id });
});
