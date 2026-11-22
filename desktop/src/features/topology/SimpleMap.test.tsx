// @vitest-environment jsdom
import {render,screen,fireEvent,cleanup} from "@testing-library/react";
import {afterEach,it,expect} from "vitest";
import {SimpleMap,simpleInventory} from "./SimpleMap";
import type {GraphDTO} from "../../types";
afterEach(cleanup);
it("reduces the model to grouped assets and retains hidden entity records",()=>{
 const data:GraphDTO={source:"neo4j",graph_id:"chosen",nodes:[
 ...["zone","host","host2","service","identity","SYN-detached"].map(id=>({id,label:id,type:id==="zone"?"network_segment":id.startsWith("host")?"host":id==="SYN-detached"?"unknown":id,metadata:{role:"User endpoints"},status:"OBSERVED",provenance:[]})),
 {id:"crown",label:"Crown asset",type:"asset",metadata:{},status:"OBJECTIVE",provenance:[]}],
 edges:[{id:"a",source:"host",target:"zone",type:"located_in",metadata:{},evidence_refs:["e"]},{id:"b",source:"host2",target:"zone",type:"located_in",metadata:{},evidence_refs:["e"]},{id:"c",source:"host",target:"crown",type:"hosts",metadata:{},evidence_refs:["e"]}]};
 expect(simpleInventory(data).assets).toHaveLength(3);
 render(<SimpleMap data={data}/>);
 expect(screen.queryByRole("button",{name:"identity"})).toBeNull();
 expect(screen.getByText("×2")).toBeTruthy();
 expect(screen.getByText("Crown asset")).toBeTruthy();
 expect(screen.getByText(/Other \/ Unassigned Assets/)).toBeTruthy();
 fireEvent.click(screen.getByRole("button",{name:"Expand groups"}));
 expect(screen.getByText("host2")).toBeTruthy();
});

it("retains a moved zone during replay and resets only presentation offsets",()=>{
 const data:GraphDTO={source:"neo4j",graph_id:"movement-test",nodes:[
 {id:"z",label:"Zone",type:"network_segment",metadata:{},status:"OBSERVED",provenance:[]},
 {id:"h",label:"Host",type:"host",metadata:{category:"workstation"},status:"OBSERVED",provenance:[]}],
 edges:[{id:"membership",source:"h",target:"z",type:"located_in",metadata:{},evidence_refs:["e"]}]};
 const view=render(<SimpleMap data={data}/>);
 const handle=screen.getByRole("button",{name:"Move Zone"});
 const group=handle.closest("section")!;
 fireEvent.keyDown(handle,{key:"ArrowRight"});
 expect(group.style.transform).toBe("translate(15px,0px)");
 view.rerender(<SimpleMap data={data} activeTarget="h"/>);
 expect(group.style.transform).toBe("translate(15px,0px)");
 fireEvent.click(screen.getByRole("button",{name:"Reset layout"}));
 expect(group.style.transform).toBe("translate(0px,0px)");
 expect(data.edges).toHaveLength(1);
});
