// @vitest-environment jsdom
import { afterEach,expect,it,vi } from "vitest";
import { cleanup,render,screen,within,waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { get,downloadReport } from "../api/client";
import { ResearchTrajectories,type ResearchTrajectory } from "./ResearchTrajectories";
import { RegisteredResearchView,type RegisteredResults } from "./RegisteredResearchView";
vi.mock("../api/client",()=>({get:vi.fn(),downloadReport:vi.fn()}));
afterEach(()=>{cleanup();vi.resetAllMocks();});
const base="research/ppo-trajectories";
const index={policies:[42,43].map(training_seed=>({training_seed,status:"AVAILABLE",episodes:[{topology_seed:1001,topology_hash:"a".repeat(64),evaluation_episode_seed:19001,episode_length:2}]}))};
function episode(seed=42):ResearchTrajectory {return {
 label:"REGISTERED PPO VALIDATION EVIDENCE — READ-ONLY RECONSTRUCTION",explanation:"Recorded evidence only",
 journey:{groups:[{offset:0,first:0,last:1,count:2,successful:2,failed:0,reward:101,targets:["synthetic-target"],techniques:["T1046"],stages:["Reconnaissance & Planning","Objective Execution / Impact"]}],notable:{"1":["Objective flag recorded"]},stages:["Reconnaissance & Planning","Objective Execution / Impact"]},
 topology_context:{registered_limits:{},structure_status:"Not recorded",limit_source:"fixture",target_ids:["synthetic-target"]},
 identity:{training_seed:seed,topology_seed:1001,topology_hash:"recorded-topology-hash",evaluation_episode_seed:19001,
  policy_sha256_before:`recorded-policy-${seed}`,checkpoint_sha256:`recorded-checkpoint-${seed}`},episode:{},
 summary:{start:"Step 0: recorded discovery",major_stages:[{category:"discover_network",first_step:0,last_step:0}],notable_actions:["Step 1: recorded final action"],notable_rule:"Recorded outcome tokens",objective_reached:true,final_action:"Step 1: access_asset:synthetic-target",total_steps:2,total_return:101,terminal_outcome:"goal",mitre_techniques:[{technique_id:"T1046"}]},
 steps:[{source_line:1,recorded:{step:0,rl_action_index:0,simulator_action:"discover_network:entry",action_kind:"discover_network",target_entity:`synthetic-target-${seed}`,reward:1,success:true,goal_reached:false,state_changed:true,prerequisites:["known:entry"],outcomes:[],framework_mappings:[{technique_id:"T1046"}]}},
  {source_line:2,recorded:{step:1,rl_action_index:930,simulator_action:"access_asset:synthetic-target",action_kind:"access_asset",target_entity:"synthetic-target",reward:100,success:true,goal_reached:true,state_changed:true,prerequisites:[],outcomes:["asset:synthetic-target"],framework_mappings:[]}}],
 chronology:{meaning:"chronological_order_only",relationship:"next_recorded_step",links:[{from_step:0,to_step:1}]},
 evidence_availability:{"Source host":"Not recorded","Access state before":"Not recorded","Access state after":"Not recorded","Observations":"Not recorded","Action masks":"Not recorded","State snapshots":"Not recorded","Policy logits":"Not recorded","Alternative actions":"Not recorded"},
 limitations:["Chronological links do not establish network connectivity"],provenance:{trajectory_file:`seed-${seed}/validation/trajectories.jsonl`,source_sha256:{"trajectories.jsonl":"source-hash"}}
};}
function backend(){vi.mocked(get).mockImplementation(async path=>path===base?index as never:episode(path.includes("/43/")?43:42) as never);}

it("shows recorded actions and chronological ordering while keeping missing evidence explicit",async()=>{
 backend();render(<ResearchTrajectories token="test-token"/>);
 await userEvent.click(await screen.findByRole("button",{name:"Combined"}));
 await userEvent.click(screen.getByRole("button",{name:"synthetic-target"}));
 expect(screen.getByText(/Recorded target association · Steps 1/)).toBeTruthy();
 expect(screen.queryByRole("list",{name:"Chronological PPO trajectory"})).toBeNull();
 await userEvent.click(screen.getByRole("button",{name:/Steps 0–1/}));
 await userEvent.click(within(screen.getByRole("list",{name:"Chronological PPO trajectory"})).getAllByRole("button")[0]);
 expect(screen.getByText(/Chronological links do not imply host-to-host network connectivity/)).toBeTruthy();
 expect(screen.getAllByText("Not recorded").length).toBeGreaterThanOrEqual(8);
 let selected=screen.getByRole("complementary",{name:"Selected recorded action"});
 expect(within(selected).getAllByText("0")).toHaveLength(2);
 expect(within(selected).getByText('false')).toBeTruthy();
 await userEvent.click(within(screen.getByRole("list",{name:"Chronological PPO trajectory"})).getAllByRole("button")[1]);
 selected=screen.getByRole("complementary",{name:"Selected recorded action"});
 expect(within(selected).getByText("930")).toBeTruthy();
 expect(within(selected).getByText("PPO selected access_asset:synthetic-target.")).toBeTruthy();
 expect(within(selected).getByText("100")).toBeTruthy();
 expect(within(selected).getByText("Why this matters")).toBeTruthy();
 await userEvent.click(screen.getByRole("button",{name:/Steps 0–1/}));
 expect(screen.queryByRole("list",{name:"Chronological PPO trajectory"})).toBeNull();
});

it("selects policies independently and downloads only the selected research episode",async()=>{
 backend();vi.mocked(downloadReport).mockResolvedValue(null);render(<ResearchTrajectories token="test-token"/>);
 await screen.findByText("recorded-policy-42");
 await userEvent.click(screen.getByRole("button",{name:"Generate Research Trajectory Report"}));
 await userEvent.selectOptions(screen.getByLabelText("Training seed / policy"),"43");
 await screen.findByText("recorded-policy-43");
 expect(screen.queryByRole("region",{name:"Research trajectory report"})).toBeNull();
 await userEvent.click(screen.getByRole("button",{name:"Generate Research Trajectory Report"}));
 for(const [label,format] of [["Download HTML","html"],["Download PDF","pdf"],["Export JSON","json"]]){
  await userEvent.click(screen.getByRole("button",{name:label}));
  expect(downloadReport).toHaveBeenCalledWith(`${base}/43/1001/19001/export/${format}`,"test-token",`research-ppo-43-1001-19001.${format}`);
 }
});

it("has explicit loading, empty and failure states without a substitute trajectory",async()=>{
 vi.mocked(get).mockImplementation(()=>new Promise(()=>{}));
 const view=render(<ResearchTrajectories token="test-token"/>);
 expect(screen.getByRole("status").textContent).toContain("Loading registered episode index");view.unmount();
 vi.mocked(get).mockResolvedValue({policies:[]});
 const empty=render(<ResearchTrajectories token="test-token"/>);
 expect(await screen.findByText(/No recorded validation episodes available/)).toBeTruthy();empty.unmount();
 vi.mocked(get).mockRejectedValue(new Error("Evidence invalid"));
 render(<ResearchTrajectories token="test-token"/>);
 expect((await screen.findByRole("alert")).textContent).toContain("Evidence invalid");
 expect(screen.queryByRole("list",{name:"Chronological PPO trajectory"})).toBeNull();
});

it("does not let an old episode response replace a newer selection",async()=>{
 let resolve:(value:unknown)=>void=()=>{};
 vi.mocked(get).mockImplementation(path=>path===base?Promise.resolve(index) as never:path.includes('/42/')?new Promise(r=>{resolve=r;}) as never:Promise.resolve(episode(43)) as never);
 render(<ResearchTrajectories token="test-token"/>);
 await waitFor(()=>expect(get).toHaveBeenCalledWith(`${base}/42/1001/19001`,"test-token",expect.any(AbortSignal)));
 await userEvent.selectOptions(screen.getByLabelText("Training seed / policy"),"43");
 await screen.findByText("recorded-policy-43");resolve(episode(42));
 await waitFor(()=>expect(screen.queryByText("recorded-policy-42")).toBeNull());
});

it("opens a separate PPO Trajectories section under Registered Research",async()=>{
 backend();const data:RegisteredResults={schema_version:"registered-results-v1",status:"AVAILABLE",read_only:true,aggregation:"per_policy",policies:[]};
 render(<RegisteredResearchView data={data} token="research-only-token"/>);
 await userEvent.click(screen.getByRole("button",{name:"PPO Trajectories"}));
 await screen.findByText("recorded-policy-42");
 expect(get).toHaveBeenCalledWith(base,"research-only-token",expect.any(AbortSignal));
 expect(screen.queryByText("Frozen registered campaign")).toBeNull();
});
