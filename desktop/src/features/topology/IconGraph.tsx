import type {ReplayState} from "../episodeState";
import {getTopologyTier,orderedNodes} from "./hierarchy";
import {useMemo,useState} from "react";
import type {GraphDTO,GraphNode,Fact} from "../../types";
import {Fields} from "../../components/EvidenceDisplay";
import type {AssessmentTopology} from "./EnterpriseStructure";

type Point={x:number;y:number};
const glyph=(type:string)=>/database/.test(type)?"▤":/identity/.test(type)?"⚿":/file/.test(type)?"▱":/security|firewall/.test(type)?"⬡":/finding|vulnerab/.test(type)?"⚠":/evidence/.test(type)?"▧":/event|action/.test(type)?"↯":/segment|zone/.test(type)?"◌":/web/.test(type)?"◎":/server/.test(type)?"▥":"▣";
export function forceLayout(nodes:GraphNode[],edges:GraphDTO["edges"]){
 const points:Record<string,Point>={};
 const membership=new Map(edges.filter(e=>e.type.toLowerCase()==="located_in").map(e=>[e.source,e.target]));
 const zones=nodes.filter(n=>/segment|zone/.test(n.type)).map(n=>n.id);
 const center=(id:string)=>{const z=zones.indexOf(membership.get(id)??id);return z<0?null:{x:175+(z%3)*315,y:160+Math.floor(z/3)*310};};
 nodes.forEach((n,i)=>{points[n.id]={x:80+(i%9)*105,y:75+Math.floor(i/9)*90};});
 for(let step=0;step<120;step++){
  const delta:Record<string,Point>=Object.fromEntries(nodes.map(n=>[n.id,{x:0,y:0}]));
  for(let a=0;a<nodes.length;a++)for(let b=a+1;b<nodes.length;b++){
   const u=nodes[a].id,v=nodes[b].id,dx=points[u].x-points[v].x,dy=points[u].y-points[v].y;
   const distance=Math.max(20,Math.hypot(dx,dy)),power=Math.min(8,2200/(distance*distance));
   delta[u].x+=dx/distance*power;delta[u].y+=dy/distance*power;delta[v].x-=dx/distance*power;delta[v].y-=dy/distance*power;
  }
  for(const edge of edges){
   const a=points[edge.source],b=points[edge.target];if(!a||!b)continue;
   const dx=b.x-a.x,dy=b.y-a.y,d=Math.max(1,Math.hypot(dx,dy)),p=(d-120)*.015;
   delta[edge.source].x+=dx/d*p;delta[edge.source].y+=dy/d*p;delta[edge.target].x-=dx/d*p;delta[edge.target].y-=dy/d*p;
  }
  for(const n of nodes){const c=center(n.id);if(c){delta[n.id].x+=(c.x-points[n.id].x)*.06;delta[n.id].y+=(c.y-points[n.id].y)*.06;}points[n.id].x=Math.max(45,Math.min(955,points[n.id].x+delta[n.id].x));points[n.id].y=Math.max(45,Math.min(655,points[n.id].y+delta[n.id].y));}
 }
 return points;
}
export function IconGraph({data,assessment,mode,activeTarget,replayState,activeSource}:{replayState?:ReplayState;activeSource?:string;activeTarget?:string;data:GraphDTO;assessment?:AssessmentTopology;mode:string}){
 const [layer,setLayer]=useState("Combined");
 const [services,setServices]=useState(false),[findings,setFindings]=useState(false),[evidence,setEvidence]=useState(false),[labels,setLabels]=useState(false);
 const [query,setQuery]=useState(""),[selected,setSelected]=useState<Fact|null>(null),[scale,setScale]=useState(1),[offset,setOffset]=useState({x:0,y:0}),[moves,setMoves]=useState<Record<string,Point>>({});
 const [hover,setHover]=useState("");
 const [drag,setDrag]=useState<{id:string;x:number;y:number}|null>(null);
 const graph=useMemo(()=>{
  if(!assessment||layer==="Observed Causal"||mode==="Evidence"||mode==="Attack / Provenance")return data;
  const raw=assessment.topology as {nodes?:{id:string;type:string;name:string;attributes:Fact}[];edges?:{source:string;target:string;type:string}[];crown_jewels?:string[]};
  const observed=new Map(data.nodes.map(n=>[n.id,n]));
  const nodes:GraphNode[]=(raw.nodes??[]).map(n=>{
    const record=layer==="Combined"&&(!replayState||replayState.known.has(n.id))?observed.get(n.id):undefined;
    const accessed=replayState?replayState.access.has(n.id):record&&String(record.metadata.current_access_level??"UNKNOWN")!=="UNKNOWN";
    return {id:n.id,type:n.type,label:n.name,metadata:{...n.attributes,...record?.metadata,...(replayState?{current_access_level:replayState.access.get(n.id)??"Not recorded"}:{}),basis:record?"Observed":"Configured",crown_jewel:raw.crown_jewels?.includes(n.id)??false,objective_status:raw.crown_jewels?.includes(n.id)?((replayState?replayState.reached.has(n.id):assessment.episodes.some(e=>e.events.some(r=>r.goal_reached===true&&r.target===n.id)))?"REACHED":"NOT REACHED"):undefined},provenance:record?.provenance??[],status:raw.crown_jewels?.includes(n.id)?"OBJECTIVE":accessed?"ACCESSED":record?"OBSERVED":"CONFIGURED"};
  });
  const ids=new Set(nodes.map(n=>n.id));
  if(mode==="Combined"&&layer==="Combined")for(const n of data.nodes)if(!ids.has(n.id)&&n.id!=="UNKNOWN"&&(!replayState||replayState.known.has(n.id)))nodes.push(n);
  const edges=(raw.edges??[]).map((e,i)=>({...e,id:"configured-"+i,metadata:{basis:"Configured"} as Fact,evidence_refs:[]}));
  return {...data,nodes,edges:mode==="Combined"&&layer==="Combined"?[...edges,...data.edges.filter(e=>e.source!=="UNKNOWN"&&(!replayState||e.evidence_refs.some(id=>replayState.evidence.has(id))))]:edges};
 },[data,assessment,mode,layer,replayState]);
 const compact=mode==="Combined"&&layer!=="Observed Causal";
 const shown=graph.nodes.filter(n=>(!compact||["host","asset","entry_point","network_segment"].includes(n.type)||services&&/service|software/.test(n.type)||findings&&/finding|vulnerability/.test(n.type)||evidence&&/evidence|identity/.test(n.type))&&(services||!/service|software/.test(n.type))&&(findings||!/finding|vulnerability/.test(n.type))&&(evidence||!/evidence/.test(n.type)));
 const membership=new Map(graph.edges.filter(e=>e.type.toLowerCase()==="located_in").map(e=>[e.source,e.target]));
 const zoneNodes=shown.filter(n=>/segment|zone/.test(n.type));
 const ids=new Set(shown.map(n=>n.id)),edges=graph.edges.filter(e=>ids.has(e.source)&&ids.has(e.target)).filter((e,i,all)=>{
  if(!compact)return true;
  if(e.metadata.basis)return ["connects","contains","located_in"].includes(e.type.toLowerCase());
  return e.metadata.success===true&&all.findIndex(x=>!x.metadata.basis&&x.type===e.type&&x.metadata.success===true)===i;
 });
 const presentation=(data.metadata?.presentation??assessment?.presentation) as {nodes:{id:string;x:number;y:number;icon:string;label:string}[];icons:Record<string,number[][][]>}|undefined;
 const points=useMemo(()=>{
  if(presentation){const result:Record<string,Point>={};for(const node of presentation.nodes)result[node.id]={x:node.x*1.8,y:node.y};for(const n of shown)if(!result[n.id])result[n.id]={x:80,y:80};return result;}
  const positions:Record<string,Point>={},counts=new Map<number,number>();
  for(const node of orderedNodes(shown)){const tier=getTopologyTier(node),i=counts.get(tier)??0;counts.set(tier,i+1);positions[node.id]={x:65+Math.min(tier,5)*170,y:70+i*80+(tier===6?400:0)};}
  return positions;
 },[data,assessment,services,findings,evidence,presentation]);
 const position=(id:string)=>moves[id]??points[id]??{x:80,y:620};
 const reset=()=>{setScale(1);setOffset({x:0,y:0});setMoves({});};
 return <section className="icon-workspace">{assessment&&mode==="Combined"&&<label>Graph layer<select value={layer} onChange={e=>{setLayer(e.target.value);setSelected(null);}}>{["Configured Topology","Observed Causal","Combined"].map(v=><option key={v}>{v}</option>)}</select></label>}
 <p>{graph.nodes.filter(n=>n.type==="host").length} systems · {data.nodes.filter(n=>n.type==="host"&&(!replayState||replayState.known.has(n.id))).length} observed hosts</p>
 <div className="graph-controls">
 <label>Search node<input value={query} onChange={e=>setQuery(e.target.value)}/></label>
 {[[services,setServices,"Show service nodes"],[findings,setFindings,"Show finding nodes"],[evidence,setEvidence,"Show evidence nodes"],[labels,setLabels,"Show edge labels"]].map(([v,set,text])=><label key={String(text)}><input type="checkbox" checked={Boolean(v)} onChange={()=> (set as (b:boolean)=>void)(!v)}/>{String(text)}</label>)}
 <button onClick={()=>setScale(v=>v*1.2)}>Zoom in</button><button onClick={()=>setScale(v=>v/1.2)}>Zoom out</button><button onClick={reset}>Fit / reset</button><button onClick={reset}>Reset layout</button>
 <button onClick={e=>void e.currentTarget.closest("section")?.requestFullscreen()}>Fullscreen</button></div>
 <p>{shown.length} visible entities · {edges.length} supported relationships · Circle labels identify assets; ★ marks the objective.</p>
 <div className="icon-graph-body"><svg viewBox="0 0 1000 700" aria-label="Interactive enterprise graph" onWheel={e=>setScale(v=>Math.max(.3,Math.min(4,v*(e.deltaY>0?.95:1.05))))}
 onPointerDown={e=>{if(e.target===e.currentTarget){setDrag({id:"",x:e.clientX,y:e.clientY});e.currentTarget.setPointerCapture(e.pointerId);}}}
 onPointerMove={e=>{if(!drag)return;const rect=e.currentTarget.getBoundingClientRect(),dx=(e.clientX-drag.x)*1000/rect.width/scale,dy=(e.clientY-drag.y)*700/rect.height/scale;if(drag.id)setMoves(v=>({...v,[drag.id]:{x:position(drag.id).x+dx,y:position(drag.id).y+dy}}));else setOffset(v=>({x:v.x+dx,y:v.y+dy}));setDrag({...drag,x:e.clientX,y:e.clientY});}} onPointerUp={()=>setDrag(null)}>
 <g transform={`translate(${offset.x} ${offset.y}) scale(${scale})`}>
 {zoneNodes.map(zone=>{const members=shown.filter(n=>n.id===zone.id||membership.get(n.id)===zone.id).map(n=>position(n.id));const xs=members.map(p=>p.x),ys=members.map(p=>p.y);const x=Math.min(...xs)-38,y=Math.min(...ys)-50;return <g key={"zone-"+zone.id} pointerEvents="none"><rect x={x} y={y} width={Math.max(...xs)-x+38} height={Math.max(...ys)-y+52} rx="45" fill="#6e9cba" fillOpacity=".06" stroke="#547c91" strokeDasharray="3 7"/><text x={x+20} y={y+20} fontSize="12">{zone.label}</text></g>})}
 {edges.map(e=>{const a=position(e.source),b=position(e.target);return <g key={e.id} onMouseEnter={()=>setHover(e.id)} onMouseLeave={()=>setHover("")} onClick={()=>setSelected({...e,relationship:e.type,basis:e.metadata.basis??"Recorded evidence"})}><path d={`M ${a.x} ${a.y} C ${(a.x+b.x)/2} ${a.y-18}, ${(a.x+b.x)/2} ${b.y+18}, ${b.x} ${b.y}`} fill="none" stroke={e.metadata.basis?"#435663":"#77c4af"} strokeWidth={e.metadata.basis?1:2}><title>{e.type.replaceAll("_"," ")}</title></path>{(labels||hover===e.id||selected?.id===e.id)&&<text x={(a.x+b.x)/2} y={(a.y+b.y)/2} fontSize="9">{e.type.replaceAll("_"," ")}</text>}</g>})}
 {shown.map(n=>{const p=position(n.id),crown=n.status==="OBJECTIVE",count=graph.edges.filter(e=>e.source===n.id&&/hosts/i.test(e.type)).length;return <g key={n.id} data-node-id={n.id} data-state={n.status} role="button" tabIndex={0} aria-label={n.label} opacity={n.status==="CONFIGURED"?.45:1} transform={`translate(${p.x} ${p.y})`} onKeyDown={e=>{if(e.key==="Enter")setSelected({...n});}} onClick={()=>setSelected({...n})} onPointerDown={e=>{e.stopPropagation();setDrag({id:n.id,x:e.clientX,y:e.clientY});e.currentTarget.setPointerCapture(e.pointerId);}}>
 <circle r={crown?23:19} fill="#172d3a" stroke={(activeTarget===n.id||activeSource===n.id)?"#ffffff":crown?"#edc779":query&&n.label.toLowerCase().includes(query.toLowerCase())?"white":"#79a6b4"} strokeWidth={activeTarget===n.id?5:activeSource===n.id?3:crown?3:1.5}/>{presentation?.nodes.find(item=>item.id===n.id)?<g>{(presentation.icons[presentation.nodes.find(item=>item.id===n.id)!.icon]??[]).map((stroke,i)=><polyline key={i} points={stroke.map(([x,y])=>`${x*1.3},${y*1.3}`).join(" ")} fill="none" stroke="#dce8ee" strokeWidth="1.5"/>)}</g>:<text textAnchor="middle" y="6" fontSize="22">{crown?"★":glyph(String(n.metadata.category??n.type))}</text>}<text textAnchor="middle" y="36" fontSize="11">{n.label.length>23?n.label.slice(0,21)+"…":n.label}{!services&&count?" +"+count:""}</text><title>{n.label} · {n.id}</title></g>})}
 </g></svg><aside className="details"><h3>Graph inspector</h3>{selected?<><Fields value={selected.metadata?{name:selected.label,type:selected.type,role:(selected.metadata as Fact).role??"Not recorded",subnet:graph.nodes.find(n=>n.id===membership.get(String(selected.id)))?.label??"Not recorded",criticality:(selected.metadata as Fact).criticality??"Not recorded",state:selected.status,basis:(selected.metadata as Fact).basis??"Observed",objective_status:(selected.metadata as Fact).objective_status??"Not applicable",services:graph.edges.filter(e=>e.source===selected.id&&/hosts/i.test(e.type)).map(e=>graph.nodes.find(n=>n.id===e.target)?.label),related_evidence:selected.provenance}:selected}/><details><summary>Canonical IDs and source record</summary><Fields value={selected}/></details><button onClick={()=>{const p=position(String(selected.id));if(p)setOffset({x:500-p.x,y:350-p.y});}}>Center selected node</button></>:<p>Select an asset or relationship.</p>}<details><summary>Technical provenance</summary><Fields value={{graph_id:data.graph_id,metadata:data.metadata,configured_identity:assessment?.identity}}/></details></aside></div>
 <p>Configured = inventory only · Observed = recorded presence · Accessed = recorded access · Detection requires explicit evidence · ★ Crown jewel · Unreached objective has no recorded goal access.</p><small>▣ Workstation · ▥ Server · ⚿ Identity · ▤ Database · ⬡ Security · ⚠ Finding · ↯ Event · ▧ Evidence · ★ Crown jewel. Lines preserve their configured or recorded basis. Position conveys no reachability claim.</small></section>;
}
