// @vitest-environment jsdom
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { NewSimulationWizard, validateWizard } from "./NewSimulationWizard";
import { EngineeringSimulations } from "./EngineeringSimulations";
import { get, post, downloadReport } from "../api/client";
import type { ExampleScenario, SimulationStatus } from "./simulationTypes";
vi.mock("../api/client",()=>({get:vi.fn(),post:vi.fn(),downloadReport:vi.fn()}));
vi.mock("./topology/GraphWorkspace",()=>({GraphWorkspace:()=> <div>Canonical recorded graph</div>}));
afterEach(()=>{cleanup();vi.resetAllMocks();});
const id="engineering-"+"a".repeat(32);
const status:SimulationStatus={enabled:true,disclaimer:"SIMULATED SECURITY ASSESSMENT — NOT A LIVE PENETRATION TEST",
 device_categories:["server"],service_categories:["HTTP"],policy:{id:"engineering-observation-heuristic-v1",label:"Existing V2 reasoning (not PPO)"},unsupported:["PPO"],
 default_spec:{name:"Synthetic test enterprise",description:"",organisation_type:"generic enterprise",scenario_label:"Synthetic test",analyst_notes:"",seed:9,hosts:2,
 subnets:[{label:"Synthetic subnet",size:2,role:"internal"}],segmentation:"balanced",dmz:false,
 devices:[{category:"server",count:2,os_family:"Linux",os_version:"synthetic",role:"synthetic host",criticality:"medium",subnet:0,internet_exposed:false,crown_jewel:true}],
 services:[{name:"HTTP",port:8080,version:"synthetic",device_group:null,accessibility:"subnet",authentication_required:true,importance:"medium"}],
 vulnerabilities:{mode:"automatic_synthetic",risk_profile:"medium",cvss_min:0,cvss_max:10,per_host:1,access:"remote",privilege:"user",service_index:0,catalogue_ids:[]},
 identity_roles:["standard user"],controls:{firewall_segmentation:true,endpoint_protection:false,mfa:false,restricted_administration:false,service_hardening:false,patch_coverage:0,monitoring:true},
 target_group:0,objective:"establish simulated access",max_steps:50,episodes:1,policy_id:"engineering-observation-heuristic-v1",action_masking:true,partial_observability:true,reward_profile:"engineering-exclusive-v1"}};

const example:ExampleScenario={preset_id:"small-office",version:1,label:"Small Office",purpose:"Synthetic editable example",
 difficulty:"Easy",critical_asset:"Synthetic files",hosts:2,subnets:1,risk_profile:"medium",segmentation:"balanced",default_seed:9,
 specification_sha256:"a".repeat(64),topology_sha256:"b".repeat(64),specification:structuredClone(status.default_spec),
 evidence_class:"engineering_simulation",research_status:"not_registered"};

it("validates host/subnet limits and reserved engineering seeds",()=>{
 expect(validateWizard({...status.default_spec,seed:16001},0)).toContain("Reserved held-out");
 expect(validateWizard({...status.default_spec,hosts:41},1)).toContain("2–40");
 expect(validateWizard({...status.default_spec,devices:[{...status.default_spec.devices[0],count:1}]},2)).toContain("Device counts");
});
it("does not create a simulation before explicit review and Create Simulation",async()=>{
 vi.mocked(post).mockImplementation(async path=>path.endsWith("preview")?{hosts:2,subnets:1,nodes:8,services:2,vulnerabilities:2,action_space_size:82,topology_sha256:"recorded-preview-hash",limitations:[]} as never:{simulation_id:id} as never);
 const created=vi.fn();render(<NewSimulationWizard token="synthetic-token" status={status} catalogue={[]} onCreated={created}/>);
 expect(screen.getByText("Step 1 / 10")).toBeTruthy();expect(post).not.toHaveBeenCalled();
 for(let i=0;i<8;i++)await userEvent.click(screen.getByRole("button",{name:"Next"}));
 await userEvent.click(screen.getByRole("button",{name:"Review Simulation"}));
 expect(await screen.findByText("recorded-preview-hash")).toBeTruthy();
 expect(post).toHaveBeenCalledTimes(1);expect(created).not.toHaveBeenCalled();
 await userEvent.click(screen.getByRole("button",{name:"Create Simulation"}));
 await waitFor(()=>expect(created).toHaveBeenCalledWith(id));
 expect(post).toHaveBeenCalledWith("engineering-simulations","synthetic-token",status.default_spec,expect.any(AbortSignal));
});
it("surfaces invalid wizard input without writing anything",async()=>{
 render(<NewSimulationWizard token="synthetic-token" status={{...status,default_spec:{...status.default_spec,seed:16001}}} catalogue={[]} onCreated={()=>{}}/>);
 await userEvent.click(screen.getByRole("button",{name:"Next"}));
 expect(screen.getByRole("alert").textContent).toContain("Reserved held-out");expect(post).not.toHaveBeenCalled();
});

function backend(completed=false){
 vi.mocked(get).mockImplementation(async path=>{
  if(path.endsWith("/status"))return status as never;
  if(path.endsWith("/catalogue"))return {items:[]} as never;
  if(path.endsWith("/examples"))return {items:[example]} as never;
  if(path==="engineering-simulations")return {items:[{simulation_id:id,name:status.default_spec.name,seed:9,created_at:"2026-11-17T00:00:00Z",completed}]} as never;
  if(path===`engineering-simulations/${id}`)return {simulation_id:id,specification:status.default_spec,specification_sha256:"spec-hash",topology_sha256:"topology-hash",topology:{},vulnerability_assignments:[]} as never;
  if(path.includes("/graph?"))return {source:"engineering-simulation",graph_id:"graph-id",nodes:[],edges:[]} as never;
  if(path.endsWith("/result"))return result as never;
  if(path.endsWith("/export/json"))return {name:"Stored assessment",summary:{systems:2,observed_findings:0,
    successful_paths:0,objective_reached:false,highest_observed_severity:"None observed"},
    findings:[],methodology:["Recorded synthetic execution"],limitations:["No live exploitation"],
    scope:{},provenance:{},remediation:{}} as never;
  throw new Error("Unexpected route");
 });
}
const result={graph_id:"graph-id",report_id:"report-id",report:{},graph:{},episodes:[{outcome:"NOT_REACHED",goal_reached:false,environment_return:-1,
 events:[{step:0,action_kind:"discover_network",source_node:"entry",target:"synthetic-subnet",success:true,reward:1,goal_reached:false,evidence_id:"stored-evidence-1",mitre_mappings:[],decision:{selection_rule:"recorded selection"}},
 {step:1,action_kind:"assess_vulnerability",source_node:"synthetic-subnet",target:"synthetic-service",success:false,reward:-2,goal_reached:false,evidence_id:"stored-evidence-2",mitre_mappings:[]}]}]};
it("runs explicitly, replays stored evidence and downloads authenticated reports",async()=>{
 backend();vi.mocked(post).mockResolvedValue(result);vi.mocked(downloadReport).mockResolvedValue(null);
 render(<EngineeringSimulations token="synthetic-token"/>);
 await userEvent.click(await screen.findByRole("button",{name:"Open assessment"}));
 expect(await screen.findByText("No simulation results yet. Run Simulation executes only the existing in-memory enterprise environment.")).toBeTruthy();
 expect(post).not.toHaveBeenCalled();await userEvent.click(screen.getByRole("button",{name:"Run Simulation"}));
 expect(await screen.findByText("stored-evidence-1")).toBeTruthy();
 await userEvent.click(screen.getByRole("button",{name:"Next step"}));expect(screen.getByText("stored-evidence-2")).toBeTruthy();
 await userEvent.click(screen.getByRole("button",{name:"Assessment Report"}));
 expect(await screen.findByRole("region",{name:"Stored simulation assessment"})).toBeTruthy();
 expect(screen.getByText("No vulnerability findings were observed in this recorded simulation.")).toBeTruthy();
 for(const [label,format] of [["Download PDF","pdf"],["Download HTML","html"],["Export JSON","json"]]){
  await userEvent.click(screen.getByRole("button",{name:label}));
  expect(downloadReport).toHaveBeenCalledWith(`engineering-simulations/${id}/export/${format}`,"synthetic-token",`${id}.${format}`);
 }
 expect(vi.mocked(post).mock.calls.every(([path])=>path===`engineering-simulations/${id}/run`)).toBe(true);
});

it("surfaces assessment load failure without displaying substitute metrics",async()=>{
 backend(true);const original=vi.mocked(get).getMockImplementation()!;
 vi.mocked(get).mockImplementation((path,...args)=>path.endsWith("/export/json")
  ?Promise.reject(new Error("Stored evidence unavailable")):original(path,...args));
 render(<EngineeringSimulations token="synthetic-token"/>);
 await userEvent.click(await screen.findByRole("button",{name:"Open assessment"}));
 await screen.findByText("stored-evidence-1");
 await userEvent.click(screen.getByRole("button",{name:"Assessment Report"}));
 expect((await screen.findByRole("alert")).textContent).toContain("Stored evidence unavailable");
 expect(screen.queryByText("Executive summary")).toBeNull();
 expect(downloadReport).not.toHaveBeenCalled();
});
it("reloads a completed saved simulation without rerunning it",async()=>{
 backend(true);render(<EngineeringSimulations token="synthetic-token"/>);
 await userEvent.click(await screen.findByRole("button",{name:"Open assessment"}));
 expect(await screen.findByText("stored-evidence-1")).toBeTruthy();expect(post).not.toHaveBeenCalled();
 expect((screen.getByRole("button",{name:"Recorded run complete"}) as HTMLButtonElement).disabled).toBe(true);
});
it("keeps unavailable runtime and backend errors explicit",async()=>{
 vi.mocked(get).mockResolvedValue({...status,enabled:false});
 render(<EngineeringSimulations token="synthetic-token"/>);
 expect(await screen.findByText(/Engineering simulation runtime unavailable/)).toBeTruthy();
 expect(post).not.toHaveBeenCalled();
});

it("loads the recorded graph filter and publishes only the selected engineering result",async()=>{
 backend(true);vi.mocked(post).mockResolvedValue({state:"EVIDENCE_READY",report_id:"report-id",graph_id:"graph-id"});
 render(<EngineeringSimulations token="synthetic-token"/>);
 await userEvent.click(await screen.findByRole("button",{name:"Open assessment"}));
 await screen.findByText("stored-evidence-1");
 await userEvent.click(screen.getByRole("button",{name:"Attack / Provenance Graph"}));
 expect(await screen.findByText("Canonical recorded graph")).toBeTruthy();
 await userEvent.selectOptions(screen.getByLabelText("Recorded graph filter"),"evidence");
 await waitFor(()=>expect(get).toHaveBeenCalledWith(`engineering-simulations/${id}/graph?view=evidence`,"synthetic-token",expect.any(AbortSignal)));
 await userEvent.click(screen.getByRole("button",{name:"Publish canonical evidence and Neo4j projection"}));
 expect(await screen.findByText("EVIDENCE_READY")).toBeTruthy();
 expect(post).toHaveBeenCalledWith(`engineering-simulations/${id}/publish`,"synthetic-token",{});
});

it("loads an editable example without creating or running records",async()=>{
 const created=vi.fn();
 render(<NewSimulationWizard token="synthetic-token" status={status} catalogue={[]} examples={[example]} onCreated={created}/>);
 await userEvent.selectOptions(screen.getByLabelText("Load example scenario"),"small-office");
 expect(post).not.toHaveBeenCalled();
 await userEvent.clear(screen.getByLabelText("Simulation name"));
 await userEvent.type(screen.getByLabelText("Simulation name"),"Edited office demonstration");
 expect(example.specification.name).toBe(status.default_spec.name);
 expect(screen.getByText("PPO: Not bound to this generated topology")).toBeTruthy();
 expect(screen.getByText("Not evaluated")).toBeTruthy();
 vi.mocked(post).mockResolvedValue({hosts:2,topology_sha256:"edited-topology",limitations:[]});
 for(let i=0;i<8;i++)await userEvent.click(screen.getByRole("button",{name:"Next"}));
 await userEvent.click(screen.getByRole("button",{name:"Review Simulation"}));
 await screen.findByRole("button",{name:"Create Simulation"});
 expect(vi.mocked(post).mock.calls[0][1]).toBe("synthetic-token");
 expect(vi.mocked(post).mock.calls[0][2]).toMatchObject({name:"Edited office demonstration",example_origin:{preset_id:"small-office",version:1}});
 expect(vi.mocked(post).mock.calls.map(([path])=>path)).toEqual(["engineering-simulations/preview"]);
 expect(created).not.toHaveBeenCalled();
});

it("opens the example browser card as a prefilled wizard without writes",async()=>{
 backend();render(<EngineeringSimulations token="synthetic-token" initialTab="examples"/>);
 expect(await screen.findByRole("region",{name:"Example scenarios"})).toBeTruthy();
 await userEvent.click(screen.getByRole("button",{name:"Use this scenario"}));
 expect((screen.getByLabelText("Simulation name") as HTMLInputElement).value).toBe(example.specification.name);
 expect(screen.getByLabelText("Load example scenario")).toHaveProperty("value","small-office");
 expect(post).not.toHaveBeenCalled();
});
