// The root layout, a server component: the React kit's provider wraps every page (@rowstile/react).
import { AuthzProvider } from "@rowstile/react";

export const metadata = { title: "rowstile conformance" };

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AuthzProvider>{children}</AuthzProvider>
      </body>
    </html>
  );
}
