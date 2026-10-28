import { expect, test } from "@playwright/test";

// Requires the disposable PostgreSQL/Neo4j fixture and real API. No API mocks.
test("persisted graph renders with Sigma and all readers show recorded evidence", async ({
  page,
}) => {
  const failures: string[] = [];
  page.on("pageerror", (error) => {
    failures.push(error.message);
    console.error("Browser error:", error.message);
  });
  await page.addInitScript(() => {
    (window as unknown as { glDraws: number }).glDraws = 0;
    for (const prototype of [
      WebGLRenderingContext.prototype,
      WebGL2RenderingContext.prototype,
    ]) {
      const original = prototype.drawArrays;
      prototype.drawArrays = function (...args: Parameters<typeof original>) {
        (window as unknown as { glDraws: number }).glDraws++;
        return original.apply(this, args);
      };
    }
    const instanced = WebGL2RenderingContext.prototype.drawArraysInstanced;
    WebGL2RenderingContext.prototype.drawArraysInstanced = function (
      ...args: Parameters<typeof instanced>
    ) {
      (window as unknown as { glDraws: number }).glDraws++;
      return instanced.apply(this, args);
    };
  });
  await page.goto("/");
  await page
    .getByLabel("Local API token")
    .fill("desktop-integration-fixture-token-0001");
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await expect(page.getByText("CONNECTED", { exact: true })).toBeVisible();
  await page
    .getByRole("button", { name: "Network Graph", exact: true })
    .click();
  await expect(page.locator("canvas.sigma-nodes")).toBeVisible();
  await expect
    .poll(() =>
      page.evaluate(() => (window as unknown as { glDraws: number }).glDraws),
    )
    .toBeGreaterThan(0);
  await expect(page.getByRole("alert")).toHaveCount(0);
  const canvas = page.locator(".canvas");
  const bounds = await canvas.boundingBox();
  if (!bounds) throw new Error("No graph viewport");
  // The fixture's four nodes use the deterministic circular presentation layout.
  const radius = (Math.min(bounds.width, bounds.height) - 60) / 2;
  await canvas.click({
    position: { x: bounds.width / 2 + radius, y: bounds.height / 2 },
  });
  await expect(page.locator("pre")).toContainText("host-a");
  // Separate single clicks from Sigma's double-click-to-zoom gesture.
  await page.waitForTimeout(400);
  await canvas.click({
    position: { x: bounds.width / 2 + radius / 2, y: bounds.height / 2 },
  });
  await expect(page.locator("pre")).toContainText("evidence_refs");
  await page.getByLabel("Search", { exact: true }).fill("host-b");
  await page.getByLabel("Node type").selectOption("service");
  await expect(page.getByLabel("Node type")).toHaveValue("service");
  await page.getByRole("button", { name: "Fit / reset" }).click();
  await page.getByRole("button", { name: "Zoom in" }).click();
  await page.getByRole("button", { name: "Zoom out" }).click();
  await page.getByLabel("Node type").selectOption("");
  await page
    .getByRole("combobox", { name: /Relationship/ })
    .selectOption("DISCOVERED");
  await page.screenshot({
    path: "test-results/populated-neo4j-sigma.png",
    fullPage: true,
  });
  await page.getByRole("button", { name: "Attack Paths", exact: true }).click();
  await page.getByLabel("Recorded path").selectOption({ index: 1 });
  await expect(
    page.getByText("AUTHENTICATED_TO", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Digital Twin", exact: true }).click();
  await expect(
    page.getByText("Persisted snapshot", { exact: false }),
  ).toBeVisible();
  const twinResponse = await page.request.get(
    "http://127.0.0.1:8765/api/digital-twin/entities",
    {
      headers: {
        Authorization: "Bearer desktop-integration-fixture-token-0001",
      },
    },
  );
  const twinEntities = await twinResponse.json();
  await expect(
    page.getByText(twinEntities[0].status, { exact: true }).first(),
  ).toBeVisible();
  await page.getByRole("button", { name: "Simulation", exact: true }).click();
  await page.getByLabel("Recorded simulation").selectOption({ index: 1 });
  await expect(
    page.getByRole("heading", { name: "Recorded episode timeline" }),
  ).toBeVisible();
  await expect(
    page.getByText("SSHLogin(host-c,svc-backup)", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Reports", exact: true }).click();
  await expect(
    page.getByText("simulation_report", { exact: true }),
  ).toBeVisible();
  expect(failures).toEqual([]);
});
