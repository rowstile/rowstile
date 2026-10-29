// What app/api/after's work saw, once it ran (404 until then)
import { done } from "@/later";

type Params = { params: Promise<{ key: string }> };

export const GET = async (_req: Request, { params }: Params) => {
  const key = decodeURIComponent((await params).key);
  const user = done.get(`${key} user`), service = done.get(`${key} service`);
  return user && service ? Response.json({ user, service }) : new Response(null, { status: 404 });
};
