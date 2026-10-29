// Jest runs the built tests (tsc -p ., in test.sh: build/tests), as ES modules (node --experimental-vm-modules),
// on two workers, each with a test database of its own (tests/workers.test.ts). The SDK's packages are measured as
// the app imports them, their built files, reported on their sources (test.sh builds them with source maps).
/** @type {import("jest").Config} */
export default {
  rootDir: "../..",
  roots: ["<rootDir>/integrations/node/build/tests"],
  testMatch: ["**/*.test.js"],
  transform: {},
  setupFilesAfterEnv: ["<rootDir>/integrations/node/build/tests/setup.js"],
  maxWorkers: 2,
  testTimeout: 120_000,
  reporters: ["default"],                // each file, then each check by its name, wherever it runs
  verbose: true,
  // `--coverage` (test.sh): the report printed, and kept with its details in CONFORMANCE_COVERAGE
  coverageProvider: "v8",
  collectCoverageFrom: ["sdk/typescript/{client,pg,drizzle,postgres,jest}/dist/*.js", "sdk/typescript/vitest/dist/core.js"],
  coverageReporters: ["text", ["text", { file: "report.txt" }], "json-summary", "json"],
  coverageDirectory: process.env.CONFORMANCE_COVERAGE ?? "integrations/node/coverage",
};
