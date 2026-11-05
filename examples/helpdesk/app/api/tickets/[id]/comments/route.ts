// A reply, or an internal note: the policy says who may write which
import { route } from "@rowstile/next";
import { inTx, requestUser } from "@/db.ts";
import { body } from "@/http.ts";

type Params = { params: Promise<{ id: string }> };

export const POST = route(async (req: Request, { params }: Params) => {
  const { id } = await params;
  const { body: text, internal = false } = await body<{ body: string; internal?: boolean }>(req);
  const me = await requestUser();
  const comment = await inTx((tx) => tx.comment.create({
    data: { ticketId: id, authorId: me, body: text, internal },
    select: { id: true },
  }));
  return Response.json(comment, { status: 201 });
});
