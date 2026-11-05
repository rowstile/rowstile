// Signing in, the example's way: by email alone, through hd.logins, which the policy doesn't govern (it says who
// someone is, not what they may do). A real app checks a password or an identity provider's token here.
import { route } from "@rowstile/next";
import { db } from "@/db.ts";
import { body, noContent } from "@/http.ts";
import { setSession } from "@/session.ts";

export const POST = route(async (req: Request) => {
  const { email } = await body<{ email: string }>(req);
  const login = await db.login.findUnique({ where: { email }, select: { userId: true } });
  if (!login) return Response.json({ title: "no one with that email" }, { status: 401 });
  await setSession({ user: login.userId });
  return Response.json({ id: login.userId });
});

export const DELETE = route(async () => {
  await setSession(null);
  return noContent();
});
