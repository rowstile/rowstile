import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// The SDK's packages, as the app imports them (their built files): test.sh builds them with source maps (tsc -b
// --sourceMap), so what the checks run of them is reported on sdk/typescript/*/src
const sdk = fileURLToPath(new URL("../../sdk/typescript/", import.meta.url));

export default defineConfig({
  test: {
    include: ["tests/**/*.test.{ts,tsx}"],
    setupFiles: ["tests/setup.ts"],
    fileParallelism: false,                  // the tests share one database, and the servers test.sh started
    testTimeout: 120_000,
    hookTimeout: 60_000,
    // `vitest run --coverage` (test.sh): the report printed, and kept with its details in CONFORMANCE_COVERAGE
    coverage: {
      provider: "v8",
      include: [`${sdk}*/dist/*.js`],
      allowExternal: true,
      reporter: ["text", ["text", { file: "report.txt" }], "json-summary", "json"],
      reportsDirectory: process.env.CONFORMANCE_COVERAGE ?? "coverage",
      reportOnFailure: true,
    },
  },
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
});
