import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./ui/e2e",
  outputDir: "./artifacts/dei-e2e/results",
  timeout: 120_000,
  expect: { timeout: 20_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [
    ["list"],
    ["html", { outputFolder: "artifacts/dei-e2e/report", open: "never" }],
    ["json", { outputFile: "artifacts/dei-e2e/results.json" }],
  ],
  use: {
    baseURL: process.env.DEI_BASE_URL || "http://localhost:8000",
    headless: process.env.DEI_HEADED === "1" ? false : true,
    ignoreHTTPSErrors: true,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    video: "retain-on-failure",
  },
});
