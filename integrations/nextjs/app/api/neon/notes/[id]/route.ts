import { route } from "@rowstile/next";
import { neon } from "@/neon";

type Params = { params: Promise<{ id: string }> };

// an update that changed nothing: expect() asks why, a hidden note is 404, one the user may not edit 403
export const PATCH = route(async (req: Request, { params }: Params) => {
  const id = Number((await params).id);
  const { body } = (await req.json()) as { body: string };
  await neon.transaction(async (c) =>
    neon.expect(await c.query("UPDATE app.notes SET body = $1 WHERE id = $2", [body, id]), "app.notes", "update", id));
  return Response.json({ id });
});

export const DELETE = route(async (_req: Request, { params }: Params) => {
  const id = Number((await params).id);
  await neon.expect(await neon.query("DELETE FROM app.notes WHERE id = $1", [id]), "app.notes", "delete", id);
  return new Response(null, { status: 204 });
});
