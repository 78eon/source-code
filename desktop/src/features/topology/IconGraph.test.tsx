// @vitest-environment jsdom
import {render,screen,fireEvent,cleanup} from "@testing-library/react";
import {afterEach,it,expect} from "vitest";
import {IconGraph,forceLayout} from "./IconGraph";
import type {GraphDTO} from "../../types";
afterEach(cleanup);
it("keeps services collapsed and exposes recorded relationships in the inspector",()=>{
 const data:GraphDTO={source:"neo4j",graph_id:"selected",nodes:["host","service"].map(id=>({id,type:id,label:id,metadata:{},provenance:[],status:"OBSERVED"})),edges:[{id:"edge",source:"host",target:"service",type:"HOSTS",metadata:{},evidence_refs:["ref"]}]};
 expect(forceLayout(data.nodes,data.edges)).toEqual(forceLayout(data.nodes,data.edges));
 render(<IconGraph data={data} mode="Evidence"/>);
 expect(screen.queryByRole("button",{name:"service"})).toBeNull();
 fireEvent.click(screen.getByLabelText("Show service nodes"));
 expect(screen.getByRole("button",{name:"service"})).toBeTruthy();
 fireEvent.click(screen.getByRole("button",{name:"host"}));
 expect(screen.getByText("Canonical IDs and source record")).toBeTruthy();
});

it("shows an unobserved configured objective without promoting it into causal evidence",()=>{
 const data:GraphDTO={source:"neo4j",graph_id:"chosen",nodes:[],edges:[]};
 const assessment={topology:{nodes:[{id:"objective",name:"Configured crown",type:"asset",attributes:{}}],edges:[],crown_jewels:["objective"]},specification:{} as import("../simulationTypes").SimulationSpec,episodes:[{goal_reached:false,events:[]}]};
 render(<IconGraph data={data} assessment={assessment} mode="Combined"/>);
 expect(screen.getByRole("button",{name:"Configured crown"})).toBeTruthy();
 fireEvent.click(screen.getByRole("button",{name:"Configured crown"}));
 expect(screen.getAllByText("NOT REACHED")[0]).toBeTruthy();
 fireEvent.change(screen.getByLabelText("Graph layer"),{target:{value:"Observed Causal"}});
 expect(screen.queryByRole("button",{name:"Configured crown"})).toBeNull();
 expect(data.nodes).toHaveLength(0);
});
