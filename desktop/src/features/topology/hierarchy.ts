import type {GraphNode} from "../../types";
export const tiers=["Entry / exposed","User / basic","Privileged / administration","Application / service","Data","Objective","Management / security","Other / Unclassified"];
export function getTopologyTier(node:GraphNode):number{
 const m=node.metadata,role=String(m.role??"").toLowerCase(),kind=String(m.category??node.type).toLowerCase();
 if(node.status==="OBJECTIVE"||m.crown_jewel===true)return 5;
 if(node.type==="entry_point"||m.internet_exposed===true)return 0;
 if(/security appliance|monitor|firewall/.test(kind+" "+role))return 6;
 if(/identity|admin|privileged|jump/.test(kind+" "+role)||["root","administrator"].includes(String(m.access_level??"")))return 2;
 if(/database/.test(kind))return 4;
 if(/web|application|file server|middleware/.test(kind))return 3;
 if(/workstation|laptop|endpoint/.test(kind))return 1;
 return 7;
}
export function orderedNodes(nodes:GraphNode[]){
 return [...nodes].sort((a,b)=>getTopologyTier(a)-getTopologyTier(b)||String(a.metadata.criticality??"").localeCompare(String(b.metadata.criticality??""))||a.id.localeCompare(b.id));
}
