// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { ManualLabSetup } from "./ManualLabSetup";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it("uses runtime values for a local plan without network requests or authorization", () => {
  const network = vi.fn();
  vi.stubGlobal("fetch", network);
  render(<ManualLabSetup />);
  fireEvent.click(screen.getByText("Manual VM setup"));
  const inputs = screen.getAllByRole("textbox") as HTMLTextAreaElement[];
  expect(inputs.every(input => input.value === "")).toBe(true);
  const target = crypto.randomUUID();
  const path = "/" + crypto.randomUUID();
  fireEvent.change(screen.getByLabelText("Target VM addresses"), { target: { value: target } });
  fireEvent.change(screen.getByLabelText("Backend ObservationScope file path"), { target: { value: path } });
  fireEvent.click(screen.getByRole("button", { name: "Prepare manual test checklist" }));
  const result = screen.getByRole("region", { name: "Manual VM checklist" });
  const plan = JSON.parse(result.querySelector("pre")!.textContent!);
  expect(plan.operator_input.targets).toBe(target);
  expect(plan.operator_input.scopeFile).toBe(path);
  expect(plan.validated).toBe(false);
  expect(plan.execution_enabled).toBe(false);
  expect(network).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Clear VM details" }));
  expect(inputs.every(input => input.value === "")).toBe(true);
  expect(screen.queryByRole("region", { name: "Manual VM checklist" })).toBeNull();
});
