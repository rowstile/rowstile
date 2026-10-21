import { useEffect, useState } from "react";
import { api, Kind, SearchPage, size } from "./api";

/** Folders and files whose name contains the words, among those the user can see: 50 of each, then more. */
export function Search({ q }: { q: string }) {
  const [result, setResult] = useState<SearchPage | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    setResult(null); setError("");
    api.search(q).then(setResult, (e) => setError(e.message));
  }, [q]);
  const download = async (id: number) => {
    try { window.location.href = (await api.downloadUrl(id)).url; } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };
  const more = async (kind: Kind, after: string) => {
    try {
      const page = await api.search(q, { kind, after });
      setResult((r) => r && (kind === "folder"
        ? { ...r, folders: [...r.folders, ...page.folders], next: { ...r.next, folder: page.next.folder } }
        : { ...r, files: [...r.files, ...page.files], next: { ...r.next, file: page.next.file } }));
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };
  const moreRow = (kind: Kind, after: string | null, label: string) => after ?
    <tr key={`more-${kind}`}><td colSpan={2}><button className="link" onClick={() => more(kind, after)}>{label}</button></td></tr> : null;
  return (
    <section>
      <h2>Search: {q}</h2>
      {error && <p className="error">{error}</p>}
      {result === null ? !error && <p className="hint">Searching...</p> :
        result.folders.length + result.files.length === 0 ? <p className="empty">Nothing found.</p> :
        <table className="list"><tbody>
          {result.folders.map((f) => <tr key={`d${f.id}`}><td className="name"><a href={`#/folder/${f.id}`}>📁 {f.name}</a></td><td /></tr>)}
          {moreRow("folder", result.next.folder, "More folders")}
          {result.files.map((f) => (
            <tr key={`f${f.id}`}>
              <td className="name"><button className="link" onClick={() => download(f.id)}>📄 {f.name}</button>{" "}
                <a className="hint" href={`#/folder/${f.folder_id}`}>open its folder</a></td>
              <td className="size">{size(f.size)}</td>
            </tr>))}
          {moreRow("file", result.next.file, "More files")}
        </tbody></table>}
    </section>
  );
}
