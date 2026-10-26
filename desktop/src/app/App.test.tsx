// @vitest-environment jsdom
import React from "react";
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App } from "./App";
import { get } from "../api/client";

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
