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
  vi.mocked(invoke).mockResolvedValue({ configured: true });
  const saved = vi.fn();
  render(
    <ConfigurationView
      initial={null}
      startupError=""
      onSaved={saved}
      onCancel={() => {}}
    />,
  );
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
