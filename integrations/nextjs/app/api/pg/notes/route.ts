// A plain query on pg: the database filters it to what the request's user may see
import { route } from "@rowstile/next";
import { sql } from "@/pg";

export const GET = route(async () => {
  const { rows } = await sql.query("SELECT id FROM app.notes ORDER BY id");
  return Response.json(rows.map((r) => r.id));
});
