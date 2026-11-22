// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it } from "vitest";
import { Details } from "./Details";
import { Identifier, Mappings } from "./EvidenceDisplay";

afterEach(cleanup);

it("copies the complete identifier while displaying its compact form", async () => {
  const user = userEvent.setup();
  const id = "ab".repeat(32);
  render(<Identifier id={id}/>);
  expect(screen.getByTitle(id).textContent).toContain("…");
  await user.click(screen.getByRole("button", {name: "Copy " + id}));
  expect(await navigator.clipboard.readText()).toBe(id);
});

it("keeps the original evidence behind a closed disclosure", () => {
  render(<Details value={{confidence: "UNKNOWN"}}/>);
  expect(screen.getByText("UNKNOWN")).toBeTruthy();
  expect(screen.getByText("View raw record").closest("details")?.open).toBe(false);
});

it("does not infer tactic or technique names from an identifier", () => {
  render(<Mappings value={[{technique_id:"recorded-id"}]}/>);
  expect(screen.getByRole("cell", {name:"recorded-id"})).toBeTruthy();
  expect(screen.getAllByRole("cell",{name:"Not recorded"})).toHaveLength(2);
});
