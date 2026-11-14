import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";

// Supplied only by an isolated disposable fixture runner. Never contains live VM inputs.
test("manual XML reaches persisted canonical views through the configured API", async ({ page }) => {
  const fixturePath = process.env.SECURITY_RL_WORKSPACE_E2E_FIXTURE;
  test.skip(!fixturePath, "requires generated disposable workspace fixture");
  const values = JSON.parse(readFileSync(fixturePath!, "utf8"));
  const token = process.env.SECURITY_RL_API_TOKEN;
  expect(token).toBeTruthy();
  await page.goto("/");
  await page.getByLabel("Local API token").fill(token!);
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await page.getByRole("button", { name: "Test / Lab Input", exact: true }).click();
  await expect(page.getByRole("option", { name: values.scope_name })).toBeAttached();
  await page.getByRole("combobox", { name: /Approved scope/ }).selectOption(values.scope_id);
  await expect(page.getByText("LIVE_LAB collection is not configured/enabled", { exact: false }))
    .toBeVisible();
  await expect(page.getByRole("button", { name: "Collect approved inventory" })).toHaveCount(0);
  for (const [label, value] of [
    ["Authorization reference", values.authorization_id], ["Target address", values.target],
    ["Permitted ports", values.ports.join(",")],
    ["Collection timestamp with timezone", values.collected_at], ["Nmap XML", values.xml],
  ]) await page.getByLabel(label, { exact: true }).fill(value);
  await page.getByLabel("Persist approved offline import").check();
  await page.getByRole("button", { name: "Process approved offline import" }).click();
  await expect(page.getByRole("region", { name: "Canonical evidence workspace" })).toBeVisible();
  await page.getByLabel("Canonical view").selectOption("report");
  await page.getByRole("button", { name: "Load canonical evidence" }).click();
  const details = page.getByLabel("Canonical evidence details");
  await expect(details).toContainText("offline-evidence-assessment-not-simulation");
  await expect(details).toContainText("UNRESOLVED");
  await expect(details).toContainText("BLOCKED");
  await expect(details).toContainText("ObservedSoftware");
  await page.getByLabel("Canonical view").selectOption("jobs");
  await page.getByRole("button", { name: "Load canonical evidence" }).click();
  await expect(details).toContainText('"state": "COMPLETE"');
});
