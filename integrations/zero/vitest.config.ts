import { defineConfig } from "vitest/config";

// The checks run one after the other: they share one database, one zero-cache and the app test.sh started.
export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    fileParallelism: false,
    reporters: ["verbose"],                  // each check by its name, as it runs
    testTimeout: 120_000,
    hookTimeout: 60_000,
  },
});
