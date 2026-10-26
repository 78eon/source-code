// @vitest-environment jsdom
import React from "react";
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TwinView, SimulationView } from "./RecordedViews";

afterEach(cleanup);
describe("persisted evidence screens", () => {
  it("keeps absent twin explicit", () => {
    render(<TwinView summary={{ status: "UNAVAILABLE" }} entities={[]} />);
    expect(
      screen.getByText("No persisted Digital Twin available"),
    ).toBeTruthy();
  });
  it("preserves twin uncertainty and opens source facts", async () => {
    render(
      <TwinView
        summary={{
          status: "AVAILABLE",
          counts: { assets: 1 },
          unresolved_conflicts: 1,
        }}
        entities={[
          {
            id: "host:1",
            entity_type: "assets",
            status: "INFERRED",
            confidence: 0.6,
            evidence_ids: ["e:1"],
          },
        ]}
      />,
    );
    expect(screen.getByText("INFERRED")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "assets" }));
    expect(screen.getByText(/"e:1"/, { selector: "pre" })).toBeTruthy();
  });
  it("keeps absent simulations explicit", () => {
    render(
      <SimulationView
        data={{
          status: "UNAVAILABLE",
          detail: "No analyst simulation reports selected",
        }}
      />,
    );
    expect(
      screen.getByText("No analyst simulation reports selected"),
    ).toBeTruthy();
  });
  it("replays persisted events without inventing outcome", async () => {
    render(
      <SimulationView
        data={{
          status: "AVAILABLE",
          items: [
            {
              id: "r:e",
              episode_id: "e",
              outcome: "UNKNOWN",
              step_count: 1,
              timeline: [
                {
                  trajectory_step: 2,
                  simulator_action: "RecordedLogin",
                  success: true,
                },
              ],
              paths: [],
            },
          ],
        }}
      />,
    );
    await userEvent.selectOptions(
      screen.getByLabelText("Recorded simulation"),
      "r:e",
    );
    expect(screen.getByText("RecordedLogin")).toBeTruthy();
    expect(screen.getByText("UNKNOWN")).toBeTruthy();
    expect(
      screen.queryByRole("button", { name: /run|train|execute/i }),
    ).toBeNull();
  });
});
