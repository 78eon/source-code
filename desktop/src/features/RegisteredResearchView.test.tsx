// @vitest-environment jsdom
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { RegisteredResearchView, type RegisteredResults } from "./RegisteredResearchView";
afterEach(cleanup);
const result: RegisteredResults = {
  schema_version: "registered-results-v1", status: "AVAILABLE", read_only: true,
  aggregation: "per_policy", policies: [{training_seed: 7, status: "AVAILABLE",
    successful_episodes: 20, episode_count: 20, success_rate: 1,
    reward_rise: false, convergence_passed: false, final_test_evaluated: false,
    mean_environment_return: -2.5, mean_failed_actions: 0,
    per_topology_success_rate: {"topology-a": 1}}],
};
it("renders per-policy 20/20, FAIL, pending and attributable topology rates", () => {
  render(<RegisteredResearchView data={result} />);
  const policy = within(screen.getByRole("region", {name: "Policy 7"}));
  expect(policy.getByText("20/20 / 100%")).toBeTruthy();
  expect(policy.getAllByText("FAIL")).toHaveLength(2);
  expect(policy.getByText("Pending / Not Evaluated")).toBeTruthy();
  expect(policy.getByText("-2.5")).toBeTruthy();
  expect(policy.getByText("0")).toBeTruthy();
  expect(policy.getByText("topology-a")).toBeTruthy();
  expect(policy.queryByText("200/200")).toBeNull();
});
it("keeps null and absent metrics unavailable without zero or PASS defaults", () => {
  render(<RegisteredResearchView data={{...result, policies: [{training_seed: 8, status: "AVAILABLE",
    mean_environment_return: null, final_test_evaluated: null}]}} />);
  expect(screen.getAllByText("Unavailable").length).toBeGreaterThan(4);
  expect(screen.queryByText("PASS")).toBeNull();
  expect(screen.queryByText("Pending / Not Evaluated")).toBeNull();
  expect(screen.getByText("Per-topology success unavailable.")).toBeTruthy();
});
it("shows unavailable campaigns and policies explicitly", () => {
  render(<RegisteredResearchView data={{...result, status: "UNAVAILABLE", policies: []}} />);
  expect(screen.getByText("No registered policy results available.")).toBeTruthy();
});

it("explains the metadata-backed PPO path separately from engineering scenarios",()=>{
 const data = {schema_version:"registered-results-v1",status:"AVAILABLE",read_only:true,aggregation:"per_policy",
  algorithm:"MaskablePPO",environment_source:"src/rlredteam/enterprise/environment.py",policies:[{training_seed:42,status:"AVAILABLE",
   policy_id:"sha256:recorded-policy",checkpoint_sha256:"recorded-checkpoint",checkpoint_binding:"Metadata binding verified",
   validation_topology_count:20,successful_episodes:20,episode_count:20,success_rate:1,reward_rise:false,
   convergence_passed:false,final_test_evaluated:false}]} as RegisteredResults;
 render(<RegisteredResearchView data={data}/>);
 expect(screen.getByRole("complementary",{name:"Where PPO is used"})).toBeTruthy();
 expect(screen.getByText(/action mask → MaskablePPO policy/)).toBeTruthy();
 expect(screen.getByText(/sha256:recorded-policy/)).toBeTruthy();
 expect(screen.getByText("Pending / Not Evaluated")).toBeTruthy();
 expect(screen.getByText("20/20 / 100%")).toBeTruthy();
 expect(screen.getAllByText("FAIL")).toHaveLength(2);
});
