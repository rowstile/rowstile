// Electric's shapes of the tickets and comments, live. The route stands in front of Electric: it asks the
// database who the request is, and hands Electric the shape the policy gives them (the sync index's rows for
// them), whatever the client sent. Nobody gets 401; a session viewing as someone gets 403, as the index holds what
// each person may read, not what a limited session may (README.md, "Live").
import { actingAs, electricShape, syncPrincipal } from "@rowstile/client";
import { sql } from "@/db.ts";
import { session } from "@/session.ts";
import { shapes } from "@/shapes.gen.ts";

async function signedIn() {
  const s = await session();
  return actingAs(s?.user ?? null, () => sql.transaction(async (c) => {
    if (s?.viewAs) await c.query("SELECT authz.view_as($1, 'the admin page: view as')", [s.viewAs]);
    return syncPrincipal(c);
  }));
}

const electric = { url: process.env.ELECTRIC_URL ?? "", secret: process.env.ELECTRIC_SECRET, signedIn, vary: ["cookie"] };
const routes = new Map<string, (req: Request) => Promise<Response>>([
  ["tickets", electricShape(shapes["hd.tickets"], electric)],
  ["comments", electricShape(shapes["hd.comments"], electric)],
]);

type Params = { params: Promise<{ table: string }> };

async function handle(req: Request, { params }: Params): Promise<Response> {
  const shape = routes.get((await params).table);
  return shape ? shape(req) : new Response(null, { status: 404 });
}

export const GET = handle;
export const POST = handle;
