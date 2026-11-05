// A key for an integration, limited to the scope intake: an admin of its workspace makes it (manage_keys), and
// sees it once
import { route } from "@rowstile/next";
import { inTx } from "@/db.ts";
import { body } from "@/http.ts";

type Params = { params: Promise<{ id: string }> };

export const POST = route(async (req: Request, { params }: Params) => {
  const { id } = await params;
  const { name } = await body<{ name: string }>(req);
  const [{ key }] = await inTx((tx) => tx.$queryRaw<{ key: string }[]>`
    SELECT authz.create_api_key(${name}, 'intake', NULL, 'integration', ${id}::text) AS key`);
  return Response.json({ key }, { status: 201 });
});
