import { defineConfig } from "drizzle-kit";

// Drizzle Kit migrates as the owner (the migration role); the app connects as conf_app (ROWSTILE_APP_URL).
// Only the app's schema is Drizzle's: rowstile's (authz, authz_gen, authz_int) come from its own migrations.
export default defineConfig({
  dialect: "postgresql",
  schema: "./src/schema.ts",
  out: "./drizzle",
  schemaFilter: ["app"],
  dbCredentials: { url: process.env.ROWSTILE_OWNER_DSN ?? "" },
});
