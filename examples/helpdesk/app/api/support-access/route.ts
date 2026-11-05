// Letting one of the vendor's staff in, for some days (a week at most, and only staff: the policy's rules)
import { route } from "@rowstile/next";
import { inTx } from "@/db.ts";
import { body, noContent } from "@/http.ts";

export const POST = route(async (req: Request) => {
  const { workspaceId, staffId, days } = await body<{ workspaceId: string; staffId: string; days: number }>(req);
  const until = new Date(Date.now() + days * 86_400_000);
  await inTx((tx) => tx.supportAccess.create({ data: { workspaceId, staffId, until }, select: { staffId: true } }));
  return noContent();
});
