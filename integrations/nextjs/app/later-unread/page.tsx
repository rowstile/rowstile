// A page whose after() reads nothing of the request while it renders: Next refuses headers() inside after() in a
// page, so user() can't find the session, and the work fails in Next's words (the checks read them in its log).
// app/later reads the user first.
import { after, connection } from "next/server";
import { db } from "@/db";

export default async function LaterUnread() {
  await connection();                               // rendered for each request, not at build
  after(async () => {
    await db.note.count();
  });
  return <p id="later-unread">sent, and the work after it fails</p>;
}
