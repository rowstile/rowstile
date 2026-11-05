// Prisma 7 reads no .env itself: dotenv loads it (test.sh sets the variables in the environment instead)
import "dotenv/config";
import { defineConfig, env } from "prisma/config";

// Prisma migrates as the tables' owner (hd_owner); the app connects as hd_app (HD_APP_URL)
export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: { path: "prisma/migrations" },
  datasource: { url: env("DATABASE_URL") },
});
