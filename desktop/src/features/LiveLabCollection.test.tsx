// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { LiveLabCollection } from "./LiveLabCollection";
import { get, post } from "../api/client";

vi.mock("../api/client", () => ({get: vi.fn(), post: vi.fn()}));
afterEach(() => {cleanup(); vi.resetAllMocks();});

it("does not offer execution when backend disables collection", async () => {
  vi.mocked(get).mockResolvedValue({enabled: false});
  render(<LiveLabCollection token={crypto.randomUUID()} />);
  await waitFor(() => expect(get).toHaveBeenCalled());
  expect(screen.queryByText("Collect approved inventory")).toBeNull();
  expect(post).not.toHaveBeenCalled();
});

it("requires a backend plan and operator confirmation, then invalidates approval on edits", async () => {
  const token = crypto.randomUUID(), scope = crypto.randomUUID(), auth = crypto.randomUUID();
  const profile = crypto.randomUUID(), target = crypto.randomUUID();
  const port = crypto.getRandomValues(new Uint16Array(1))[0] || 1;
  const checksum = crypto.randomUUID().replaceAll("-", "").repeat(2);
  vi.mocked(get).mockResolvedValue({enabled: true, profile, budget: {},
    scopes: [{scope_id: scope, name: scope, authorization_id: auth}]});
  render(<LiveLabCollection token={token} />);
  await screen.findByRole("option", {name: scope});
  fireEvent.change(screen.getByLabelText("Live approved scope"), {target: {value: scope}});
  fireEvent.change(screen.getByLabelText("Live target address"), {target: {value: target}});
  fireEvent.change(screen.getByLabelText("Live ports"), {target: {value: String(port)}});
  vi.mocked(post).mockResolvedValueOnce({plan_digest: checksum, scope_validated: true, budget: {}});
  fireEvent.click(screen.getByText("Validate live plan (no scan)"));
  await screen.findByLabelText("Validated live plan");
  expect(post).toHaveBeenCalledWith("workspace/live/plan", token, {
    scope_id: scope, authorization_id: auth, target, ports: [port], profile,
  }, expect.any(AbortSignal));
  expect((screen.getByText("Collect approved inventory") as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(screen.getByLabelText("I approve this exact lab collection"));
  expect((screen.getByText("Collect approved inventory") as HTMLButtonElement).disabled).toBe(false);
  fireEvent.change(screen.getByLabelText("Live target address"), {target: {value: crypto.randomUUID()}});
  expect(screen.queryByText("Collect approved inventory")).toBeNull();
  expect(post).toHaveBeenCalledTimes(1);
});
