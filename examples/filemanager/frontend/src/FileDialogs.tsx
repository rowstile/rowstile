import { useEffect, useRef, useState } from "react";
import { api, size, Version } from "./api";

/** A file shown in the browser: images, PDF, text, audio and video. */
export function PreviewDialog({ id, name, onClose }: { id: number; name: string; onClose: () => void }) {
  const [shown, setShown] = useState<{ url: string; content_type: string } | null>(null);
  const [text, setText] = useState<string | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    api.previewUrl(id).then(async (p) => {
      setShown(p);
      if (p.content_type === "text/plain") setText(await (await fetch(p.url)).text());
    }, (e) => setError(e.message));
  }, [id]);
  const download = async () => {
    setError("");
    try { window.location.href = (await api.downloadUrl(id)).url; } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };
  const t = shown?.content_type ?? "";
  return (
    <div className="modal" onClick={onClose}><div className="box wide" onClick={(e) => e.stopPropagation()}>
      <h3>{name}</h3>
      {error && <p className="error">{error}</p>}
      {shown && <div className="preview">
        {t.startsWith("image/") && <img src={shown.url} alt={name} />}
        {t === "application/pdf" && <iframe src={shown.url} title={name} />}
        {t.startsWith("audio/") && <audio src={shown.url} controls />}
        {t.startsWith("video/") && <video src={shown.url} controls />}
        {t === "text/plain" && <pre>{text ?? "Loading..."}</pre>}
      </div>}
      <div className="buttons">
        <button className="link" onClick={download}>Download</button>
        <button onClick={onClose}>Close</button>
      </div>
    </div></div>
  );
}

/** Every version of a file: upload a new one, download or bring back an old one. */
export function VersionsDialog({ id, name, canEdit, onClose }: { id: number; name: string; canEdit: boolean; onClose: () => void }) {
  const [versions, setVersions] = useState<Version[] | null>(null);
  const [progress, setProgress] = useState("");
  const [error, setError] = useState("");
  const pick = useRef<HTMLInputElement>(null);
  const load = () => api.versions(id).then(setVersions, (e) => setError(e.message));
  useEffect(() => { load(); }, [id]);
  const run = async (fn: () => Promise<unknown>) => {
    setError("");
    try { await fn(); await load(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };
  return (
    <div className="modal" onClick={onClose}><div className="box wide" onClick={(e) => e.stopPropagation()}>
      <h3>Versions of {name}</h3>
      {versions === null ? <p className="hint">{error || "Loading..."}</p> :
        <table className="list"><tbody>
          {versions.map((v) => (
            <tr key={v.id}>
              <td>{new Date(v.created_at).toLocaleString()}{v.current && <span className="tag">current</span>}</td>
              <td className="hint">{v.created_by_name}</td>
              <td className="size">{size(v.size)}</td>
              <td className="actions">
                <button className="link" onClick={() => run(async () => { window.location.href = (await api.versionUrl(v.id)).url; })}>
                  Download</button>
                {canEdit && !v.current && <button className="link" onClick={() => run(() => api.restoreVersion(v.id))}>Make current</button>}
              </td>
            </tr>))}
        </tbody></table>}
      {progress && <p className="hint">{progress}</p>}
      {error && <p className="error">{error}</p>}
      <div className="buttons">
        {canEdit && <>
          <button onClick={() => pick.current?.click()}>Upload a new version</button>
          <input ref={pick} type="file" hidden onChange={(e) => {
            const f = e.target.files?.[0];
            e.target.value = "";
            if (f) run(async () => {
              try { await api.uploadVersion(id, f, (x) => setProgress(`Uploading: ${Math.round(x * 100)}%`)); }
              finally { setProgress(""); }
            });
          }} />
        </>}
        <button className="link" onClick={onClose}>Close</button>
      </div>
    </div></div>
  );
}
