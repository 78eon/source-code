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
  await expect(page.getByText("Current workspace", {exact:true})).toBeVisible();
  await page.screenshot({path:"test-results/dashboard.png"});
  await page.getByRole("button",{name:"Vulnerabilities",exact:true}).click();
  await expect(page.getByRole("heading",{name:"Vulnerabilities",exact:true})).toBeVisible();
  await expect(page.getByText("Loading recorded evidence…")).toHaveCount(0);
  await page.screenshot({path:"test-results/vulnerabilities.png"});
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
  await page.getByText("Inspect by name",{exact:true}).click();
  await page.getByLabel("Inspect node",{exact:true}).selectOption("host-a");
  await expect(page.locator(".details pre")).toContainText("host-a");
  await page.getByLabel("Inspect relationship",{exact:true}).selectOption({index:1});
  await expect(page.locator(".details pre")).toContainText("evidence_refs");
  await page.getByLabel("Graph mode").selectOption("Topology");
  await expect(page.getByText("Enterprise Topology Structure",{exact:true})).toBeVisible();
  await page.getByLabel("Graph mode").selectOption("Attack / Provenance");
  await expect(page.locator("canvas.sigma-nodes")).toBeVisible();
  await page.getByLabel("Graph mode").selectOption("Combined");
  await expect(page.getByText("Topology Profile",{exact:true})).toBeVisible();
  await page.getByLabel("Graph mode").selectOption("Evidence");
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
    page.getByRole("heading",{name:"AUTHENTICATED_TO",exact:true}),
  ).toBeVisible();
  await page.screenshot({path:"test-results/attack-paths.png"});
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
