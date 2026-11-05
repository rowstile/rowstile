import type { ReactNode } from "react";
import { Suspense } from "react";
import { Who } from "@/ui/who.tsx";

export const metadata = { title: "Helpdesk" };

const css = `
body { font: 15px/1.45 system-ui, sans-serif; margin: 0; color: #1d2330; background: #f6f7f9; }
header { display: flex; gap: 16px; align-items: center; padding: 10px 20px; background: #1d2330; color: #fff; }
header a { color: #cfd8ff; text-decoration: none; }
main { max-width: 900px; margin: 20px auto; padding: 0 16px; }
table { width: 100%; border-collapse: collapse; background: #fff; }
td, th { padding: 6px 10px; border-bottom: 1px solid #e3e6eb; text-align: left; }
.internal { background: #fff7e0; }
.problem { background: #fdecec; border: 1px solid #f1b5b5; padding: 8px 12px; white-space: pre-wrap; }
.tag { font-size: 12px; padding: 1px 6px; border-radius: 8px; background: #e3e6eb; }
form, section { background: #fff; padding: 12px; margin: 12px 0; border: 1px solid #e3e6eb; }
textarea { box-sizing: border-box; display: block; margin-bottom: 8px; font: inherit; }
label { margin-right: 12px; }
`;

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <style>{css}</style>
        <header>
          <strong>Helpdesk</strong>
          <a href="/inbox">Inbox</a>
          <a href="/admin">Admin</a>
          <span style={{ marginLeft: "auto" }}><Suspense><Who /></Suspense></span>
        </header>
        <main>{children}</main>
      </body>
    </html>
  );
}
