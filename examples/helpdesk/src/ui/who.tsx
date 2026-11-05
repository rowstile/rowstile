// Who is signed in, and whom an admin views the app as: read as the request's user, like everything else
import { inTx } from "@/db.ts";
import { session } from "@/session.ts";

export async function Who() {
  const s = await session();
  if (!s) return <a href="/">sign in</a>;
  const me = await inTx((tx) => tx.$queryRaw<{ name: string }[]>`SELECT name FROM hd.users_visible WHERE id = authz.uid()`);
  return (
    <span>
      {s.viewAs ? <>viewing as <b>{me[0]?.name ?? "?"}</b> (read-only)</> : me[0]?.name ?? "?"}
    </span>
  );
}
