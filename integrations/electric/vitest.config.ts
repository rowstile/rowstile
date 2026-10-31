import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// The checks run one after the other: they share one database, one Electric and the servers test.sh started. What
// they run of Electric's proxy in the SDK (@rowstile/client's electric.js, built with source maps by test.sh) is
// reported on its source, sdk/typescript/client/src/electric.ts.
const client = fileURLToPath(new URL("../../sdk/typescript/client/dist/", import.meta.url));

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    fileParallelism: false,
    reporters: ["verbose"],                  // each check by its name, as it runs
    testTimeout: 120_000,
    hookTimeout: 60_000,
    // `vitest run --coverage` (test.sh): the report printed, and kept with its details in CONFORMANCE_COVERAGE
    coverage: {
      provider: "v8",
      include: [`${client}electric.js`],
      allowExternal: true,
      reporter: ["text", ["text", { file: "report.txt" }], "json-summary", "json"],
      reportsDirectory: process.env.CONFORMANCE_COVERAGE ?? "coverage",
      reportOnFailure: true,
    },
  },
});
