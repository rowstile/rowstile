// Prisma 7 reads no .env itself: dotenv loads it (test.sh sets the variables in the environment instead)
import "dotenv/config";
import { defineConfig, env } from "prisma/config";

// Prisma migrates as the owner (the migration role); the app connects as conf_app (ROWSTILE_APP_URL)
export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: { path: "prisma/migrations" },
  datasource: { url: env("DATABASE_URL") },
});
