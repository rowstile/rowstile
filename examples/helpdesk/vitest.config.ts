import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// The API's checks, over HTTP against the server test.sh started, one after the other (they share its database)
export default defineConfig({
  test: { include: ["tests/**/*.test.ts"], fileParallelism: false, testTimeout: 60_000 },
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
});
