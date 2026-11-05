// Routes live in the URL's hash: #/, #/folder/12, #/requests, #/review/3, #/groups, #/search/words
import { useEffect, useState } from "react";

export type Route =
  | { page: "home" }
  | { page: "folder"; id: number }
  | { page: "requests" }
  | { page: "review"; id: number }
  | { page: "groups" }
  | { page: "search"; q: string }
  | { page: "link"; kind: "folder" | "file"; id: number; token: string; at: number | null };

export function parse(hash: string): Route {
  const [, page, id, third, fourth, fifth] = hash.replace(/^#/, "").split("/");
  // #/link/folder/12/<token>[/<folder inside it>]
  if (page === "link" && (id === "folder" || id === "file") && Number(third) > 0 && fourth)
    return { page, kind: id, id: Number(third), token: fourth, at: Number(fifth) > 0 ? Number(fifth) : null };
  if (page === "folder" && Number(id) > 0) return { page, id: Number(id) };
  if (page === "review" && Number(id) > 0) return { page, id: Number(id) };
  if (page === "requests" || page === "groups") return { page };
  if (page === "search" && id) return { page, q: decoded(id) };
  return { page: "home" };
}

/** The words of a link the app wrote (encoded), or of one typed by hand as it stands ("50%" is no escape). */
function decoded(text: string): string {
  try { return decodeURIComponent(text); } catch { return text; }
}

export const go = (path: string) => { window.location.hash = path; };

export function useRoute(): Route {
  const [route, setRoute] = useState(() => parse(window.location.hash));
  useEffect(() => {
    const on = () => setRoute(parse(window.location.hash));
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return route;
}
