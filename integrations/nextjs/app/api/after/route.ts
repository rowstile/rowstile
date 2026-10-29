// Work once the response is sent (Next's after()): as the request's user, read from the request as every
// transaction is, and as service 1 with job(). Neither carries over to the next request.
import { after } from "next/server";
import { job } from "@rowstile/client";
import { route } from "@rowstile/next";
import { db } from "@/db";
import { done } from "@/later";

const who = async () => (await db.$queryRaw<{ who: string }[]>`SELECT coalesce((SELECT principal_type || ' ' || principal_id FROM authz.principal()), 'nobody') AS who`)[0].who;

export const POST = route(async (req: Request) => {
  const { key } = (await req.json()) as { key: string };
  after(async () => {
    const notes = (await db.note.findMany({ select: { id: true }, orderBy: { id: "asc" } })).map((n) => n.id);
    done.set(`${key} user`, { who: await who(), notes });
  });
  after(job(["service", 1], async () => {
    const projects = (await db.project.findMany({ select: { id: true }, orderBy: { id: "asc" } })).map((p) => p.id);
    done.set(`${key} service`, { who: await who(), projects });
  }));
  return new Response(null, { status: 202 });
});
