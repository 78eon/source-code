// @vitest-environment jsdom
import { render, screen, fireEvent, waitFor, cleanup, act } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { CanonicalWorkspace } from "./CanonicalWorkspace";
import { get } from "../api/client";

vi.mock("../api/client", () => ({ get: vi.fn() }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });
it("uses operator-selected canonical IDs without simulation fallback", async () => {
  const id = crypto.randomUUID().replaceAll("-", "").repeat(2), token = crypto.randomUUID();
  const source = crypto.randomUUID();
  vi.mocked(get).mockResolvedValueOnce({items: [{correlation_id: id, snapshot_id: crypto.randomUUID(), graph_id: crypto.randomUUID()}]});
  render(<CanonicalWorkspace token={token} />);
  await screen.findByRole("option", {name: id});
  fireEvent.change(screen.getByLabelText("Persisted correlation"), {target: {value: id}});
  fireEvent.change(screen.getByLabelText("Canonical view"), {target: {value: "advisory"}});
  fireEvent.change(screen.getByLabelText("Persistent source node IDs"), {target: {value: source}});
  vi.mocked(get).mockResolvedValueOnce({data: {state: "BLOCKED"}});
  fireEvent.click(screen.getByText("Load canonical evidence"));
  await waitFor(() => expect(get).toHaveBeenLastCalledWith(`workspace/correlations/${id}/advisory?source_id=${source}`, token, expect.any(AbortSignal)));
  expect(await screen.findByLabelText("Canonical evidence details")).toBeTruthy();
  expect(screen.getByLabelText("Canonical evidence details").textContent).toContain("BLOCKED");
});
it("shows missing backend data without invented inventory", async () => {
  vi.mocked(get).mockRejectedValue(new Error(crypto.randomUUID()));
  render(<CanonicalWorkspace token={crypto.randomUUID()} />);
  expect((await screen.findByRole("alert")).textContent).toContain("No simulation or substitute");
  expect((screen.getByText("Load canonical evidence") as HTMLButtonElement).disabled).toBe(true);
});

it("does not display a pending previous job response after the selected job changes", async () => {
  const token = crypto.randomUUID(), oldJob = crypto.randomUUID(), newJob = crypto.randomUUID();
  let finish!: (value: unknown) => void;
  vi.mocked(get).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  const view = render(<CanonicalWorkspace token={token} importedJobId={oldJob} />);
  fireEvent.click(screen.getByText("Load canonical evidence"));
  await waitFor(() => expect(get).toHaveBeenCalledTimes(1));
  view.rerender(<CanonicalWorkspace token={token} importedJobId={newJob} />);
  await act(async () => { finish({oldJob}); });
  expect(screen.queryByLabelText("Canonical evidence details")).toBeNull();
  expect((screen.getByText("Load canonical evidence") as HTMLButtonElement).disabled).toBe(false);
});

it("shows correlations loading instead of a premature empty state", async () => {
  let finish!: (value: unknown) => void;
  vi.mocked(get).mockImplementationOnce(() => new Promise(resolve => {finish = resolve;}));
  render(<CanonicalWorkspace token="test" />);
  expect(screen.getByText("Loading persisted correlations…")).toBeTruthy();
  expect(screen.queryByText("No persisted canonical correlations available.")).toBeNull();
  await act(async () => {finish({items: []});});
  expect(screen.getByText("No persisted canonical correlations available.")).toBeTruthy();
});
