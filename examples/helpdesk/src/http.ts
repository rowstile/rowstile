// What the route handlers share: the request's JSON body, typed by the handler that reads it.
export async function body<T>(req: Request): Promise<T> {
  return (await req.json()) as T;
}

export const noContent = (): Response => new Response(null, { status: 204 });
