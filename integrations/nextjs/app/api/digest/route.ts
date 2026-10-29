// The request's user queues the digest; the worker (src/queue.ts) runs it as service 1
import { route } from "@rowstile/next";
import { digests } from "@/queue";

export const POST = route(async () => Response.json({ id: (await digests().add("digest", {})).id }, { status: 202 }));
