// @vitest-environment jsdom
import { cleanup, render, screen, fireEvent } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { GraphWorkspace } from "./GraphWorkspace";
vi.mock("sigma", () => ({default: vi.fn()}));
afterEach(cleanup);
it("exposes backend graph identity, provenance and display limits", () => {
  render(<GraphWorkspace data={{source: "neo4j", graph_id: "stored-graph", nodes: [], edges: [],
    metadata: {total_nodes: 30, displayed_nodes: 10, projection: {report_id: "stored-report"}}}} />);
  fireEvent.click(screen.getByRole("button",{name:"Expert Graph"}));
  expect(screen.getByText("Graph: stored-graph")).toBeTruthy();
  expect(screen.getByText(/"total_nodes": 30/, {selector: "pre"})).toBeTruthy();
  expect(screen.getByText(/stored-report/, {selector: "pre"})).toBeTruthy();
});
