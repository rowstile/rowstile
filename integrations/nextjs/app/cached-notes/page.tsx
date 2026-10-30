// A page that tries to cache what one user may see (check 15): @rowstile/next refuses to sign in inside the
// cache, so the page fails instead of serving one user's notes to the next.
import { Suspense } from "react";
import { unstable_cache } from "next/cache";
import { actingAs } from "@rowstile/client";
import { db, requestUser } from "@/db";

const cachedNotes = unstable_cache(async () => db.note.findMany({ select: { id: true }, orderBy: { id: "asc" } }), ["notes"]);

async function CachedNotes() {
  const user = await requestUser();
  const notes = await actingAs(user, () => cachedNotes());
  return (
    <ul id="notes">
      {notes.map((n) => <li key={n.id} data-note={n.id} />)}
    </ul>
  );
}

// Cache Components (create-next-app's default) wants what reads the request inside <Suspense>
export default function Page() {
  return <Suspense><CachedNotes /></Suspense>;
}
