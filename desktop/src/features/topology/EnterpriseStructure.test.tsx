// @vitest-environment jsdom
import {fireEvent,render,screen,within,cleanup} from "@testing-library/react";
import {afterEach,expect,it} from "vitest";
import {EnterpriseStructure} from "./EnterpriseStructure";
import type {GraphDTO} from "../../types";
import type {SimulationSpec} from "../simulationTypes";
afterEach(cleanup);
const data:GraphDTO={nodes:[],edges:[],source:"engineering-simulation",graph_id:null};
it.each([24,40])("groups %i systems and restricts playback to known entities",size=>{
 const make=(id:string,type:string)=>({id,name:id,type,attributes:{}});
 const hosts=Array.from({length:size},(_,i)=>make("system-"+i,"host"));
 const zones=["first zone","second zone"].map(id=>make(id,"network_segment"));
 const topo={entry_points:["origin"],crown_jewels:["objective"],nodes:[...zones,...hosts,make("origin","entry_point"),make("objective","asset"),make("test service","service")],
 edges:[...hosts.map((h,i)=>({source:h.id,target:zones[i%2].id,type:"located_in"})),{source:hosts[0].id,target:"test service",type:"hosts"}]};
 render(<EnterpriseStructure data={data} combined assessment={{topology:topo,specification:{} as SimulationSpec,episodes:[{goal_reached:false,events:[{step:0,target:hosts[0].id,success:true,action_kind:"enumerate_host",knowledge_delta:{discovered_nodes:[zones[0].id],observed_edges:[[hosts[0].id,zones[0].id,"located_in"]]}}]}]}}/>);
 const zone=screen.getByRole("button",{name:"first zone"}).closest("section")!;
 expect(within(zone).getAllByRole("button",{name:/^system-/})).toHaveLength(size/2);
 expect(screen.queryByRole("button",{name:/test service/})).toBeNull();
 expect(screen.getAllByRole("button",{name:/★ objective/}).length).toBeGreaterThan(0);
 fireEvent.click(screen.getByRole("button",{name:"Expand services"}));
 expect(screen.getByRole("button",{name:/test service/})).toBeTruthy();
 fireEvent.click(screen.getByRole("button",{name:"Collapse services"}));
 expect(screen.queryByRole("button",{name:/test service/})).toBeNull();
 fireEvent.click(screen.getByLabelText("Show access / reachability"));
 expect(screen.getByText(/Reachability not established/)).toBeTruthy();
 fireEvent.click(screen.getByLabelText("Step through observed topology"));
 expect(screen.queryByRole("button",{name:/^system-/})).toBeNull();
 expect(screen.queryByText(/Objective not reached/)).toBeNull();
 fireEvent.click(screen.getByRole("button",{name:"Next step"}));
 expect(screen.getAllByRole("button",{name:/^system-/})).toHaveLength(1);
 expect(screen.queryByText("second zone")).toBeNull();
});

it("keeps a Neo4j observation separate from configured reachability",()=>{
 const graph:GraphDTO={...data,source:"neo4j",
 nodes:["left","right"].map(id=>({id,label:id,type:"host",metadata:{},status:"OBSERVED",provenance:["ref"]})),
 edges:[{id:"edge",source:"left",target:"right",type:"AUTHENTICATED_TO",metadata:{success:true,step:2},evidence_refs:["ref"]}]};
 render(<EnterpriseStructure data={graph} combined/>);
 fireEvent.click(screen.getByLabelText("Show access / reachability"));
 expect(screen.getByRole("button",{name:/left → right.*Recorded relationship/})).toBeTruthy();
 expect(screen.getByText("Membership unavailable")).toBeTruthy();
 expect(screen.getByText("Not explicitly modelled")).toBeTruthy();
});
