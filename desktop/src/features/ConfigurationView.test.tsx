// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { invoke } from "@tauri-apps/api/core";
import { ConfigurationView, offlineDemo } from "./ConfigurationView";
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});
it("first-run demo saves explicitly without database credentials", async () => {
  vi.mocked(invoke).mockResolvedValue({ configured: true, settings: offlineDemo, settings_path: "/private/settings.json" });
  const saved = vi.fn();
  render(
    <ConfigurationView
      initial={null}
      startupError=""
      onSaved={saved}
      onCancel={() => {}}
    />,
  );
  expect(screen.getByText("Technical details").closest("details")?.open).toBe(false);
  await userEvent.click(
    screen.getByRole("button", { name: "Save and open workspace" }),
  );
  expect(invoke).toHaveBeenCalledWith("desktop_configuration", {
    operation: "save",
    payload: { settings: offlineDemo, passwords: { postgres: "", neo4j: "" } },
  });
  expect(saved).toHaveBeenCalledOnce();
});
it("shows keyring failure without claiming settings were saved", async () => {
  vi.mocked(invoke).mockRejectedValue(
    "OS Secret Service is locked or unavailable",
  );
  const saved = vi.fn();
  render(
    <ConfigurationView
      initial={null}
      startupError=""
      onSaved={saved}
      onCancel={() => {}}
    />,
  );
  await userEvent.click(screen.getByLabelText("Use external PostgreSQL"));
  await userEvent.type(
    screen.getByLabelText("PostgreSQL password"),
    "test-password",
  );
  await userEvent.click(
    screen.getByRole("button", { name: "Save and open workspace" }),
  );
  expect(await screen.findByRole("alert")).toBeTruthy();
  expect(saved).not.toHaveBeenCalled();
  expect(localStorage.length).toBe(0);
});

it("sends replacement passwords, then blank reuse, and surfaces classified failures", async () => {
  const initial = {...offlineDemo, postgres: {host: "127.0.0.1", port: 5433,
    database: "synthetic", user: "reader", sslmode: "disable"},
    neo4j: {uri: "bolt://127.0.0.1:7687", database: "neo4j", user: "reader"}};
  vi.mocked(invoke).mockImplementation(async (_command, args) => {
    if ((args as {operation: string}).operation === "save") return {configured: true, settings: (args as {payload: {settings: unknown}}).payload.settings, settings_path: "/private/settings.json"} as never;
    return {checks: {postgres: "CONNECTED (read-only session)",
      neo4j: "UNAVAILABLE [AUTHENTICATION_FAILED]: Re-enter the correct database password in Settings."}, offline: false} as never;
  });
  render(<ConfigurationView initial={initial} startupError="" onSaved={() => {}} onCancel={() => {}} />);
  await userEvent.type(screen.getByLabelText("PostgreSQL password"), "replacement-pg");
  await userEvent.type(screen.getByLabelText("Neo4j password"), "replacement-neo");
  await userEvent.click(screen.getByRole("button", {name: "Save and check connections"}));
  expect((await screen.findByRole("status")).textContent).toContain("AUTHENTICATION_FAILED");
  expect(invoke).toHaveBeenCalledWith("desktop_configuration", {operation: "save", payload: {
    settings: initial, passwords: {postgres: "replacement-pg", neo4j: "replacement-neo"}}});
  expect((screen.getByLabelText("PostgreSQL password") as HTMLInputElement).value).toBe("");
  expect((screen.getByLabelText("Neo4j password") as HTMLInputElement).value).toBe("");
  await userEvent.click(screen.getByRole("button", {name: "Save and check connections"}));
  expect(invoke).toHaveBeenLastCalledWith("desktop_configuration", {operation: "check"});
  expect(vi.mocked(invoke).mock.calls.filter(([, args]) => (args as {operation: string}).operation === "save").at(-1)?.[1])
    .toEqual({operation: "save", payload: {settings: initial, passwords: {postgres: "", neo4j: ""}}});
});

it("saves the exact loopback Neo4j URI with its entered password before checking connections", async () => {
  const initial = {...offlineDemo,
    postgres: {host: "127.0.0.1", port: 5433, database: "synthetic", user: "reader", sslmode: "disable"},
    neo4j: {uri: "bolt://localhost:7687", database: "neo4j", user: "neo4j"}};
  vi.mocked(invoke).mockImplementation(async (_command,args) =>
    (args as {operation:string}).operation === "save" ? {configured:true, settings:(args as {payload: {settings: unknown}}).payload.settings, settings_path:"/private/settings.json"} as never
    : {checks:{postgres:"CONNECTED (read-only session)",neo4j:"CONNECTED (read query)"},offline:false} as never);
  render(<ConfigurationView initial={initial} startupError="" onSaved={()=>{}} onCancel={()=>{}} />);
  expect(screen.getByText(/Changing the Neo4j address/)).toBeTruthy();
  await userEvent.clear(screen.getByLabelText("Neo4j uri"));
  await userEvent.type(screen.getByLabelText("Neo4j uri"),"bolt://127.0.0.1:7687");
  await userEvent.type(screen.getByLabelText("Neo4j password"),"new-synthetic-only");
  await userEvent.click(screen.getByRole("button",{name:"Save and check connections"}));
  expect((await screen.findByRole("status")).textContent).toContain("neo4j: CONNECTED");
  expect(screen.getByRole("status").textContent).toContain("postgres: CONNECTED");
  expect(vi.mocked(invoke).mock.calls[0]).toEqual(["desktop_configuration",{operation:"save",payload:{
    settings:{...initial,neo4j:{...initial.neo4j,uri:"bolt://127.0.0.1:7687"}},
    passwords:{postgres:"",neo4j:"new-synthetic-only"}}}]);
  expect(vi.mocked(invoke).mock.calls[1]).toEqual(["desktop_configuration",{operation:"check"}]);
  expect((screen.getByLabelText("Neo4j password") as HTMLInputElement).value).toBe("");
});

it("confirms persistence and updates the parent cache even when the subsequent check fails", async () => {
  const initial = {...offlineDemo, neo4j: {uri:"bolt://localhost:7687", user:"neo4j", database:"neo4j"}};
  const onPersisted = vi.fn();
  vi.mocked(invoke).mockImplementation(async (_command, args) => {
    if ((args as {operation:string}).operation === "save") return {
      configured:true, settings:(args as {payload:{settings:unknown}}).payload.settings,
      settings_path:"/app/desktop-config/org.securityrl.analyst/settings.json"} as never;
    throw "Connection check could not complete";
  });
  render(<ConfigurationView initial={initial} startupError="" onSaved={()=>{}}
    onCancel={()=>{}} onPersisted={onPersisted} settingsPath="/app/desktop-config/org.securityrl.analyst/settings.json" />);
  await userEvent.clear(screen.getByLabelText("Neo4j uri"));
  await userEvent.type(screen.getByLabelText("Neo4j uri"),"bolt://127.0.0.1:7687");
  await userEvent.type(screen.getByLabelText("Neo4j password"),"synthetic-password");
  await userEvent.click(screen.getByRole("button",{name:"Save and check connections"}));
  expect((await screen.findByRole("alert")).textContent).toContain("Connection check could not complete");
  expect(screen.getByText(/Settings saved and read back/).textContent).toContain("bolt://127.0.0.1:7687");
  expect((screen.getByLabelText("Neo4j uri") as HTMLInputElement).value).toBe("bolt://127.0.0.1:7687");
  expect(onPersisted).toHaveBeenCalledWith({...initial,neo4j:{...initial.neo4j,uri:"bolt://127.0.0.1:7687"}},
    "/app/desktop-config/org.securityrl.analyst/settings.json");
  expect((screen.getByLabelText("Neo4j password") as HTMLInputElement).value).toBe("");
});

it("does not check connections without a verified save response", async () => {
  vi.mocked(invoke).mockResolvedValue({configured:true});
  render(<ConfigurationView initial={null} startupError="" onSaved={()=>{}} onCancel={()=>{}} />);
  await userEvent.click(screen.getByRole("button",{name:"Save and check connections"}));
  expect((await screen.findByRole("alert")).textContent).toContain("save confirmation is missing");
  expect(invoke).toHaveBeenCalledTimes(1);
});
