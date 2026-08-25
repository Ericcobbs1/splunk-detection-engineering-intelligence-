import { test, expect } from "@playwright/test";

const app = "/en-US/app/splunk_detection_engineering_intelligence";
const username = process.env.SPLUNK_USERNAME;
const password = process.env.SPLUNK_PASSWORD;

if (!username || !password) {
  throw new Error("SPLUNK_USERNAME and SPLUNK_PASSWORD are required. Use npm run test:release to enter them locally.");
}

async function login(page) {
  await page.goto(`${app}/dei_home`, { waitUntil: "domcontentloaded" });
  if (/\/account\/login/.test(page.url())) {
    await page.getByLabel("Username").fill(username);
    await page.getByLabel("Password").fill(password);
    await Promise.all([
      page.waitForURL(new RegExp(`${app}/`), { timeout: 30_000 }),
      page.getByRole("button", { name: "Sign In" }).click(),
    ]);
  }
  await expect(page).toHaveURL(new RegExp(`${app}/`));
}

function collectRuntimeFailures(page, failures) {
  page.on("pageerror", error => failures.push(`pageerror: ${error.message}`));
  page.on("console", message => {
    if (message.type() === "error") failures.push(`console: ${message.text()}`);
  });
  page.on("response", response => {
    const url = response.url();
    if (response.status() >= 500 && url.includes("splunk_detection_engineering_intelligence")) {
      failures.push(`http ${response.status()}: ${url}`);
    }
  });
}

test.describe.serial("DEI public release gate", () => {
  test.beforeEach(async ({ page }) => login(page));

  test("all owned pages render without browser or server failures", async ({ page }) => {
    const failures = [];
    collectRuntimeFailures(page, failures);
    const views = [
      "dei_home", "detection_workflow", "command_center", "environment_insights",
      "mitre_coverage", "mitre_heatmap", "detection_catalog",
      "detection_action_center", "detection_health", "dei_help",
    ];
    for (const view of views) {
      const response = await page.goto(`${app}/${view}`, { waitUntil: "domcontentloaded" });
      expect(response?.status(), `${view} HTTP response`).toBeLessThan(400);
      await expect(page.locator("body")).not.toContainText(/500 Internal Server Error|Page not found|An error occurred/i);
      await expect(page.locator("body")).toContainText(/DEI|Detection|Environment|Coverage|Help/i);
    }
    expect(failures, failures.join("\n")).toEqual([]);
  });

  test("home controls and pipeline destinations remain operational", async ({ page }) => {
    await page.goto(`${app}/dei_home`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("button", { name: /Refresh pipeline/i })).toBeEnabled();
    await page.getByRole("button", { name: /Refresh pipeline/i }).click();
    await expect(page.getByRole("button", { name: /Refresh pipeline/i })).toBeEnabled({ timeout: 90_000 });
    await expect(page.locator("body")).not.toContainText("refresh timed out");
    await expect(page.getByRole("button", { name: /Take a tour/i })).toBeEnabled();
    const destinations = await page.locator("[data-home-flow-stage]").count();
    expect(destinations).toBeGreaterThanOrEqual(7);
  });

  test("library selection exposes Generate and tutorial cannot outrun readiness", async ({ page }) => {
    const failures = [];
    collectRuntimeFailures(page, failures);
    await page.goto(`${app}/detection_workflow`, { waitUntil: "domcontentloaded" });
    const workflowSelect = page.locator("#workflow-detection-select");
    await expect(workflowSelect).toBeVisible();
    await expect.poll(async () => workflowSelect.locator('option[value^="library:"]').count()).toBeGreaterThan(0);
    const option = workflowSelect.locator('option[value^="library:"]').first();
    const value = await option.getAttribute("value");
    expect(value).toBeTruthy();
    await workflowSelect.selectOption(value);

    const generate = page.locator("#builder-generate");
    await expect(page.locator("#detection-generator")).toBeVisible();
    await expect(generate).toBeVisible();
    await expect(generate).toBeEnabled();
    const workflowId = String(value).replace(/^library:/, "");
    await expect(page.locator("#builder-detection-select")).toHaveValue(workflowId);

    await generate.click();
    await expect(page.locator("#generator-output")).toBeVisible({ timeout: 60_000 });
    await expect(page.locator("#generator-spl")).not.toHaveValue("");
    await expect(page.locator("body")).not.toContainText("Required control unavailable");
    expect(failures, failures.join("\n")).toEqual([]);
  });

  test("generated detection reaches bounded validation and preserves navigation", async ({ page }) => {
    await page.goto(`${app}/detection_workflow`, { waitUntil: "domcontentloaded" });
    const workflowSelect = page.locator("#workflow-detection-select");
    await expect.poll(async () => workflowSelect.locator('option[value^="library:"]').count()).toBeGreaterThan(0);
    const value = await workflowSelect.locator('option[value^="library:"]').first().getAttribute("value");
    await workflowSelect.selectOption(value);
    await page.locator("#builder-generate").click();
    await expect(page.locator("#generator-output")).toBeVisible({ timeout: 60_000 });
    await page.locator("#builder-run-validation").click();
    await expect(page.locator("#builder-run-validation")).toBeEnabled({ timeout: 90_000 });
    await expect(page.locator("#builder-validation-state")).not.toContainText(/not run|running/i);
    await expect(page.locator("#workflow-tab-change-control")).toBeEnabled();
    await page.locator("#workflow-tab-change-control").click();
    await expect(page.locator("#lifecycle-action-center")).toBeVisible();
    await page.locator("#workflow-tab-artifact").click();
    await expect(page.locator("#guided-builder-workspace")).toBeVisible();
  });
});
