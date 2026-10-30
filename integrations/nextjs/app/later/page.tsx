// A page that writes once it is sent (Next's after()): no render is left then, and no cache to keep the transaction
// out of, so it signs in as the reader and runs. The reader sends user 2 a message.
import { Suspense } from "react";
import { after } from "next/server";
import { actingAs } from "@rowstile/client";
import { db, requestUser } from "@/db";

async function Later() {
  const reader = await requestUser();
  after(() => actingAs(reader, () =>
    db.$executeRaw`INSERT INTO app.inbox (sender_id, recipient_id, body) VALUES (${Number(reader ?? 0)}, 2, 'later')`));
  return <p id="later">sent once the page is</p>;
}

// Cache Components (create-next-app's default) wants what reads the request inside <Suspense>
export default function Page() {
  return <Suspense><Later /></Suspense>;
}
