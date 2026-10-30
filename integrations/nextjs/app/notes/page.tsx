// A signed-in page: the notes the request's user may see. No checks here: the database filters the rows.
import { Suspense } from "react";
import { db } from "@/db";

async function Notes() {
  const notes = await db.note.findMany({ select: { id: true, body: true }, orderBy: { id: "asc" } });
  return (
    <ul id="notes">
      {notes.map((n) => <li key={n.id} data-note={n.id}>{n.body}</li>)}
    </ul>
  );
}

// Cache Components (create-next-app's default) wants what reads the request inside <Suspense>
export default function Page() {
  return <Suspense><Notes /></Suspense>;
}
