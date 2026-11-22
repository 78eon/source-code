import {it,expect} from "vitest";
import {getTopologyTier,orderedNodes} from "./hierarchy";
import type {GraphNode} from "../../types";
const node=(id:string,category:string,role=""):GraphNode=>({id,label:id,type:"host",metadata:{category,role},status:"CONFIGURED",provenance:[]});
it("classifies explicit roles and retains ambiguous nodes",()=>{
 expect(getTopologyTier({...node("a","server"),status:"OBJECTIVE"})).toBe(5);
 expect(getTopologyTier(node("b","database server"))).toBe(4);
 expect(getTopologyTier(node("c","application server"))).toBe(3);
 expect(getTopologyTier(node("d","identity server"))).toBe(2);
 expect(getTopologyTier(node("e","workstation"))).toBe(1);
 expect(getTopologyTier(node("f","security appliance"))).toBe(6);
 expect(getTopologyTier(node("g","unknown"))).toBe(7);
 const nodes=[node("b","database server"),node("a","workstation")];
 expect(orderedNodes(nodes)).toEqual(orderedNodes([...nodes].reverse()));
 expect(nodes[0].id).toBe("b");
});
