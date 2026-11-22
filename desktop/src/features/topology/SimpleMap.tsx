import {getTopologyTier,orderedNodes,tiers} from "./hierarchy";
import {useMemo,useState,useEffect} from "react";
import type {Fact,GraphDTO,GraphNode} from "../../types";
import type {AssessmentTopology} from "./EnterpriseStructure";
import {Fields} from "../../components/EvidenceDisplay";

export function simpleInventory(data:GraphDTO,assessment?:AssessmentTopology){
 const topology=assessment?.topology as {nodes?:{id:string;name:string;type:string;attributes:Fact}[];edges?:{source:string;target:string;type:string}[];crown_jewels?:string[]}|undefined;
 const nodes:GraphNode[]=topology?.nodes?.map(n=>({id:n.id,label:n.name,type:n.type,metadata:n.attributes,status:topology.crown_jewels?.includes(n.id)?"OBJECTIVE":"CONFIGURED",provenance:[]}))??data.nodes;
 const edges=topology?.edges??data.edges;
 const membership=new Map(edges.filter(e=>e.type.toLowerCase()==="located_in").map(e=>[e.source,e.target]));
 // Only explicit containment/membership can locate a crown asset.
 for(let i=0;i<nodes.length;i++)for(const e of edges)if(["hosts","contains"].includes(e.type.toLowerCase())&&membership.has(e.source)&&!membership.has(e.target))membership.set(e.target,membership.get(e.source)!);
 const zones=nodes.filter(n=>/^(network_segment|segment|zone)$/.test(n.type));
 const assets=nodes.filter(n=>n.type==="host"||n.type==="entry_point"||n.status==="OBJECTIVE");
 return {nodes,edges,membership,zones,assets};
}
const symbol=(n:GraphNode)=>n.status==="OBJECTIVE"?"★":/database/.test(String(n.metadata.category))?"▤":/server/.test(String(n.metadata.category))?"▥":/security/.test(String(n.metadata.category))?"⬡":"▣";
export function SimpleMap({data,assessment,activeTarget}:{data:GraphDTO;assessment?:AssessmentTopology;activeTarget?:string}){
 const model=useMemo(()=>simpleInventory(data,assessment),[data,assessment]);
 const [expanded,setExpanded]=useState(false),[other,setOther]=useState(false),[selected,setSelected]=useState<GraphNode[]|null>(null),[collapsed,setCollapsed]=useState<string[]>([]),[zoom,setZoom]=useState(1);
 const layoutKey="security-rl-layout:"+String(data.graph_id??assessment?.specification.name??"unbound");
 const [positions,setPositions]=useState<Record<string,{x:number;y:number}>>(()=>{
   try{return JSON.parse(sessionStorage.getItem(layoutKey)??"{}");}catch{return {};}
 });
 useEffect(()=>{try{sessionStorage.setItem(layoutKey,JSON.stringify(positions));}catch{/* Storage can be disabled by the desktop profile. */}},[layoutKey,positions]);
 const [drag,setDrag]=useState<{id:string;x:number;y:number}|null>(null);
 const zones=useMemo(()=>[...model.zones].sort((a,b)=>{
   const score=(z:GraphNode)=>Math.min(...model.assets.filter(n=>model.membership.get(n.id)===z.id).map(getTopologyTier),7);
   return score(a)-score(b)||a.id.localeCompare(b.id);
 }),[model]);
 const groups=zones.map(z=>({id:z.id,label:z.label,assets:model.assets.filter(n=>model.membership.get(n.id)===z.id)}));
 const unassigned=model.nodes.filter(n=>!model.zones.some(z=>z.id===n.id)&&!model.membership.has(n.id)&&n.type!=="entry_point");
 const entry=model.assets.filter(n=>n.type==="entry_point");
 const cards=(assets:GraphNode[])=>{
  const grouped=new Map<string,GraphNode[]>();
  for(const n of orderedNodes(assets)){const key=expanded?n.id:n.status==="OBJECTIVE"?n.id:JSON.stringify([n.type,n.metadata.category,n.metadata.role,n.metadata.criticality]);grouped.set(key,[...(grouped.get(key)??[]),n]);}
  return [...grouped.values()].map(items=><button className={"simple-asset "+(items.some(n=>n.id===activeTarget)?"active ":"")+(items[0].status==="OBJECTIVE"?"crown":"")} key={items[0].id} onClick={()=>setSelected(items)} title={items.map(n=>n.label).join(", ")}>
    <span aria-hidden="true">{symbol(items[0])}</span><span className="simple-label">{items.length>1?String(items[0].metadata.role??items[0].metadata.category??items[0].type):items[0].label}</span>{items.length>1&&<b>×{items.length}</b>}
  </button>);
 };
 return <section className="simple-map"><div className="graph-controls"><button onClick={()=>setZoom(1)}>Fit</button><button onClick={()=>{setZoom(1);setExpanded(false);setCollapsed([]);setSelected(null);setPositions({});}}>Reset</button><button onClick={()=>setPositions({})}>Reset layout</button><button onClick={()=>setExpanded(true)}>Expand groups</button><button onClick={()=>setExpanded(false)}>Collapse groups</button></div>
 <div className="simple-map-body"><div className="simple-map-zones" style={{zoom}}>
 <div className="simple-entry">{cards(entry)}</div>
 {groups.map(group=><section className="simple-zone" key={group.id} style={{transform:`translate(${positions[group.id]?.x??0}px,${positions[group.id]?.y??0}px)`}}>
 <span role="button" tabIndex={0} aria-label={"Move "+group.label} className="group-handle"
 onKeyDown={e=>{const direction:Record<string,[number,number]>={ArrowLeft:[-15,0],ArrowRight:[15,0],ArrowUp:[0,-15],ArrowDown:[0,15]};const delta=direction[e.key];if(delta){e.preventDefault();setPositions(p=>({...p,[group.id]:{x:(p[group.id]?.x??0)+delta[0],y:(p[group.id]?.y??0)+delta[1]}}));}}}
 onPointerDown={e=>{setDrag({id:group.id,x:e.clientX,y:e.clientY});e.currentTarget.setPointerCapture(e.pointerId);}}
 onPointerMove={e=>{if(drag?.id!==group.id)return;const dx=(e.clientX-drag.x)/zoom,dy=(e.clientY-drag.y)/zoom;setPositions(p=>({...p,[group.id]:{x:(p[group.id]?.x??0)+dx,y:(p[group.id]?.y??0)+dy}}));setDrag({...drag,x:e.clientX,y:e.clientY});}}
 onPointerUp={()=>setDrag(null)}>Move group</span><button className="simple-zone-title" onClick={()=>setCollapsed(v=>v.includes(group.id)?v.filter(x=>x!==group.id):[...v,group.id])}>{group.label} — {group.assets.filter(n=>n.type==="host").length} assets</button>{!collapsed.includes(group.id)&&<div className="tier-lanes">{tiers.map((title,tier)=>{const members=group.assets.filter(n=>getTopologyTier(n)===tier);return members.length?<div key={title} className="tier-lane"><small>{title}</small><div className="simple-devices">{cards(members)}</div></div>:null;})}</div>}</section>)}
 {unassigned.length>0&&<details open={other} onToggle={e=>setOther(e.currentTarget.open)} className="simple-unassigned"><summary>Other / Unassigned Assets ({unassigned.length})</summary>{other&&cards(unassigned)}</details>}
 </div><aside className="details"><h3>{selected?"System details":"How to read this map"}</h3>{selected?<><Fields value={{names:selected.map(n=>n.label),type:selected[0].type,role:selected[0].metadata.role??"Not recorded",services:model.edges.filter(e=>selected.some(n=>n.id===e.source)&&e.type==="hosts").filter(e=>model.nodes.find(n=>n.id===e.target)?.type==="service").length,identities:model.edges.filter(e=>selected.some(n=>n.id===e.source)&&e.type==="yields_credential").length}}/><details><summary>Technical IDs and evidence</summary><Fields value={selected}/><Fields value={{graph_id:data.graph_id,metadata:data.metadata}}/></details></>:<ul><li>Each dotted area represents a network zone.</li><li>Each icon represents a simulated system or grouped systems.</li><li>The star marks the crown jewel.</li><li>Bright outlines show the current recorded target.</li><li>Click a system for details.</li></ul>}<p>Zone order is a layout convention. Connectivity requires recorded relationships.</p></aside></div></section>;
}
