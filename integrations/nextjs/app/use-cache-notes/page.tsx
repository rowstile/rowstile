// The same as cached-notes, with the "use cache" directive (check 15): what one user may see doesn't go into
// that cache either. Next gives a cached function no request and nothing of what was set around it
// (actingAs), so the SDK asks the app's `user` function, which reads the request's headers: Next refuses
// that inside a cache, and the page fails instead of serving one user's notes to the next.
import { Suspense } from "react";
import { actingAs } from "@rowstile/client";
import { db, requestUser } from "@/db";

async function cachedNotes() {
  "use cache";
  return db.note.findMany({ select: { id: true }, orderBy: { id: "asc" } });
}

async function UseCacheNotes() {
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
  return <Suspense><UseCacheNotes /></Suspense>;
}
