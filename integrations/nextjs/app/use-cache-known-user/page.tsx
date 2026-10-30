// "use cache" where the user doesn't come from the request (check 15): a client whose `user` function knows
// who it is without reading anything Next would refuse inside a cache. Only @rowstile/next stands in the way
// here: before a transaction signs in as someone it calls connection(), which throws inside a cache. Without
// it this page would cache user 1's notes and serve them to whoever asks.
import { Suspense } from "react";
import { PrismaPg } from "@prisma/adapter-pg";
import { authz, signedIn } from "@rowstile/prisma";
import "@rowstile/next";
import { pool, requestUser } from "@/db";
import { PrismaClient } from "@/generated/prisma/client.ts";

const asOne = new PrismaClient({ adapter: signedIn(new PrismaPg(pool), { user: async () => "1" }) }).$extends(authz());

async function cachedNotes() {
  "use cache";
  return asOne.note.findMany({ select: { id: true }, orderBy: { id: "asc" } });
}

async function UseCacheKnownUser() {
  await requestUser();        // the page is rendered for each request (left static, the build itself refuses it)
  const notes = await cachedNotes();
  return (
    <ul id="notes">
      {notes.map((n) => <li key={n.id} data-note={n.id} />)}
    </ul>
  );
}

// Cache Components (create-next-app's default) wants what reads the request inside <Suspense>
export default function Page() {
  return <Suspense><UseCacheKnownUser /></Suspense>;
}
