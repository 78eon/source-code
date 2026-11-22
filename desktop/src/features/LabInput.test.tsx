// @vitest-environment jsdom
import { render, screen, fireEvent, waitFor, act } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { cleanup } from "@testing-library/react";
import { LabInput } from "./LabInput";
import { get, post } from "../api/client";

const randomUUID = () => crypto.randomUUID();
const randomInt = (min: number, max: number) =>
  min + crypto.getRandomValues(new Uint32Array(1))[0] % (max - min);

vi.mock("../api/client", () => ({ get: vi.fn(), post: vi.fn() }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });

it("starts empty and forwards only runtime operator input", async () => {
  const scope = randomUUID(), token = randomUUID(), auth = randomUUID();
  const target = Array.from({ length: 4 }, () => randomInt(1, 255)).join(".");
  const port = randomInt(1, 65536);
  const at = new Date().toISOString();
  const xml = "<nmaprun/>";
  vi.mocked(get).mockResolvedValue([{ scope_id: scope, name: scope }]);
  vi.mocked(post).mockResolvedValue({ persisted: false });
  render(<LabInput token={token} />);
  expect((screen.getByLabelText("Target address") as HTMLInputElement).value).toBe("");
  await screen.findByRole("option", { name: scope });
  for (const [label, value] of [
    ["Approved scope", scope], ["Authorization reference", auth], ["Target address", target],
    ["Permitted ports", String(port)], ["Collection timestamp with timezone", at], ["Nmap XML", xml],
  ]) fireEvent.change(screen.getByLabelText(label), { target: { value } });
  fireEvent.click(screen.getByRole("button", { name: "Validate offline preview" }));
  await waitFor(() => expect(post).toHaveBeenCalledWith("lab-input/preview", token, {
    scope_id: scope, authorization_id: auth, target, ports: [port], collected_at: at, xml,
  }));
});

it("fails closed when approved scopes are unavailable", async () => {
  vi.mocked(get).mockRejectedValue(new Error(randomUUID()));
  render(<LabInput token={randomUUID()} />);
  await screen.findByRole("alert");
  expect((screen.getByRole("button", { name: "Validate offline preview" }) as HTMLButtonElement).disabled).toBe(true);
  expect(post).not.toHaveBeenCalled();
});

it("ignores old scope responses after the connection token changes", async () => {
  const oldScope = randomUUID(), newScope = randomUUID();
  let finish!: (value: unknown) => void;
  vi.mocked(get).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  vi.mocked(get).mockResolvedValueOnce([{scope_id: newScope, name: newScope}]);
  const view = render(<LabInput token={randomUUID()} />);
  view.rerender(<LabInput token={randomUUID()} />);
  await screen.findByRole("option", {name: newScope});
  await act(async () => { finish([{scope_id: oldScope, name: oldScope}]); });
  expect(screen.queryByRole("option", {name: oldScope})).toBeNull();
  expect(screen.getByRole("option", {name: newScope})).toBeTruthy();
});

it("clears a previous connection error when the new connection supplies approved scopes", async () => {
  vi.mocked(get).mockRejectedValueOnce(new Error(randomUUID()));
  const view = render(<LabInput token={randomUUID()} />);
  await screen.findByRole("alert");
  const scope = randomUUID();
  vi.mocked(get).mockResolvedValueOnce([{scope_id: scope, name: scope}]);
  view.rerender(<LabInput token={randomUUID()} />);
  await screen.findByRole("option", {name: scope});
  expect(screen.queryByRole("alert")).toBeNull();
});

it("opens imported assessment views while keeping manual notes out of the API payload", async () => {
  const token = randomUUID(), scope = randomUUID(), auth = randomUUID();
  const job = randomUUID(), note = randomUUID();
  const target = Array.from({ length: 4 }, () => randomInt(1, 255)).join(".");
  const port = randomInt(1, 65536), at = new Date().toISOString();
  const xml = `<nmaprun version="${randomUUID()}"/>`;
  vi.mocked(get).mockImplementation(async (path) => path === "lab-input/scopes"
    ? [{scope_id: scope, name: scope}] : {enabled: false});
  vi.mocked(post).mockResolvedValue({events: [{job_id: job, state: "COMPLETE"}]});
  render(<LabInput token={token} allowOfflineProcessing />);
  fireEvent.click(screen.getByText("Manual VM setup"));
  fireEvent.change(screen.getByLabelText("Collector interface"), {target: {value: note}});
  fireEvent.click(screen.getByRole("button", {name: "Prepare manual test checklist"}));
  await screen.findByRole("option", {name: scope});
  for (const [label, value] of [
    ["Approved scope", scope], ["Authorization reference", auth], ["Target address", target],
    ["Permitted ports", String(port)], ["Collection timestamp with timezone", at], ["Nmap XML", xml],
  ]) fireEvent.change(screen.getByLabelText(label), {target: {value}});
  fireEvent.click(screen.getByLabelText("Persist approved offline import"));
  fireEvent.click(screen.getByRole("button", {name: "Process approved offline import"}));
  await screen.findByRole("region", {name: "Canonical evidence workspace"});
  expect(post).toHaveBeenCalledExactlyOnceWith("workspace/jobs/offline", token, {
    scope_id: scope, authorization_id: auth, target, ports: [port], collected_at: at, xml,
  });
  vi.mocked(get).mockResolvedValueOnce({data: {advisory: {state: "BLOCKED"}}, import_provenance: {}});
  fireEvent.change(screen.getByLabelText("Canonical view"), {target: {value: "report"}});
  fireEvent.click(screen.getByRole("button", {name: "Load canonical evidence"}));
  await waitFor(() => expect(get).toHaveBeenLastCalledWith(`workspace/jobs/${job}/views/report?`, token, expect.any(AbortSignal)));
  expect((await screen.findByLabelText("Canonical evidence details")).textContent).toContain("BLOCKED");
  expect(get).toHaveBeenCalledTimes(3);
});

it("labels pending scope loading and then a successful empty response", async () => {
  let finish!: (value: unknown) => void;
  vi.mocked(get).mockImplementationOnce(() => new Promise(resolve => {finish = resolve;}));
  render(<LabInput token="test" />);
  expect(screen.getByText("Loading approved scopes…")).toBeTruthy();
  expect(screen.queryByText("No backend-approved offline scopes available.")).toBeNull();
  await act(async () => {finish([]);});
  expect(screen.getByText("No backend-approved offline scopes available.")).toBeTruthy();
});
