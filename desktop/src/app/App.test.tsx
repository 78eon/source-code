// @vitest-environment jsdom
import React from "react";
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App } from "./App";
import { get } from "../api/client";
import { invoke, isTauri } from "@tauri-apps/api/core";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn(), isTauri: vi.fn(() => false) }));

vi.mock("../api/client", () => ({ get: vi.fn(), configureOrigin: vi.fn() }));
vi.mock("../features/topology/GraphWorkspace", () => ({
  GraphWorkspace: () => <div>Graph workspace</div>,
}));
afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});

it("shows loading while graph request is pending", async () => {
  vi.mocked(get).mockResolvedValue([]);
  render(<App />);
  await waitFor(() =>
    expect(screen.queryByText("Loading recorded evidence…")).toBeNull(),
  );
  vi.mocked(get).mockImplementation((path) =>
    path === "health" ? (Promise.resolve({}) as never) : new Promise(() => {}),
  );
  await userEvent.click(screen.getByRole("button", { name: "Network Graph" }));
  expect(screen.getByText("Loading recorded evidence…")).toBeTruthy();
});

it("shows source failure without substitute graph", async () => {
  vi.mocked(get).mockImplementation((path) =>
    path === "graph/topology"
      ? Promise.reject(new Error("Data source unavailable"))
      : (Promise.resolve([]) as never),
  );
  render(<App />);
  await userEvent.click(screen.getByRole("button", { name: "Network Graph" }));
  expect(await screen.findByRole("alert")).toBeTruthy();
  expect(screen.queryByText("Graph workspace")).toBeNull();
});

it("requires first-run configuration before starting the native backend", async () => {
  vi.mocked(isTauri).mockReturnValue(true);
  vi.mocked(invoke).mockResolvedValue({ configured: false, settings: null });
  render(<App />);
  expect(await screen.findByText("Configure your analyst workspace")).toBeTruthy();
  expect(invoke).toHaveBeenCalledWith("desktop_configuration", { operation: "get" });
  expect(vi.mocked(invoke).mock.calls.some(([command]) => command === "backend_session")).toBe(false);
  expect(get).not.toHaveBeenCalled();
});

it("opens a configured native workspace through its owned backend", async () => {
  vi.mocked(isTauri).mockReturnValue(true);
  vi.mocked(invoke).mockImplementation(async (command) => {
    if (command === "desktop_configuration") return { configured: true, settings: { profile: "demo" } } as never;
    return { origin: "http://127.0.0.1:12345", token: "test-owned-session" } as never;
  });
  vi.mocked(get).mockResolvedValue([]);
  render(<App />);
  await waitFor(() => expect(invoke).toHaveBeenCalledWith("backend_session"));
  expect(await screen.findByText(/Demo profile ·/)).toBeTruthy();
  await waitFor(() => expect(get).toHaveBeenCalled());
});
