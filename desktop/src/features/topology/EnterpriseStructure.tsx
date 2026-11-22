import { useEffect, useState } from "react";
import type { Fact, GraphDTO } from "../../types";
import type { SimulationSpec } from "../simulationTypes";
import { Fields, Mappings } from "../../components/EvidenceDisplay";

type Node = { id:string; name:string; type:string; attributes:Fact };
type Edge = { source:string; target:string; type:string };
export type AssessmentTopology = {
  recordedFindings?:number; identity?:Fact; presentation?:unknown; topology:Fact; specification:SimulationSpec;
  episodes:{events:Fact[];goal_reached:boolean}[];
};
const unknown = "Not recorded";
const readable = (value:string) => value.replaceAll("_"," ");
const accessTypes = new Set(["connects","pivots_to","has_access","authenticated_to","connected_to","grants_access","reachable","restricted","blocked"]);
const children = new Set(["hosts","contains","yields_credential","exposes"]);
const valid = (id:unknown): id is string => typeof id==="string" && !!id && id.toUpperCase()!=="UNKNOWN";

export function EnterpriseStructure({data,assessment,combined}:{data:GraphDTO;assessment?:AssessmentTopology;combined:boolean}) {
  const [index,setIndex]=useState(0),[playback,setPlayback]=useState(false),[count,setCount]=useState(0);
  const [access,setAccess]=useState(false),[controls,setControls]=useState(false),[expanded,setExpanded]=useState("");
  const [selected,setSelected]=useState(""),[relation,setRelation]=useState<Fact|null>(null);
  const episode=assessment?.episodes[index],events=episode?.events??[];
  const [playing,setPlaying]=useState(false);
  const [showFailures,setShowFailures]=useState(false),[allServices,setAllServices]=useState(false);
  const stops=events.flatMap((row,i)=>showFailures||row.success===true?[i+1]:[]);
  const next=stops.find(i=>i>count);
  const prev=stops.filter(i=>i<count).at(-1)??0;
  const limited=combined && playback && !!episode;
  useEffect(()=>{
    if(!playing||!limited||next==null){setPlaying(false);return;}
    const timer=setTimeout(()=>{setCount(next);setSelected("");setRelation(null);},700);
    return ()=>clearTimeout(timer);
  },[playing,limited,next]);
  const history=limited?events.slice(0,count):events;
  const nodes=(assessment?.topology.nodes as Node[]|undefined)??data.nodes.map(n=>({id:n.id,name:n.label,type:n.type,attributes:n.metadata}));
  const configured=(assessment?.topology.edges as Edge[]|undefined)??[];
  const known=new Set<string>((assessment?.topology.entry_points as string[])??[]);
  const targets=new Set<string>(),first=new Map<string,number>(),levels=new Map<string,string>();
  const observed:Edge[]=[];
  const projectedStages=assessment?[]:data.edges.filter(e=>e.evidence_refs.length&&e.metadata.success===true&&e.metadata.step!=null)
    .sort((a,b)=>String(a.metadata.episode_id).localeCompare(String(b.metadata.episode_id))||Number(a.metadata.step)-Number(b.metadata.step));
  for(const edge of projectedStages)targets.add(edge.target);
  for(const row of history){
    const delta=(row.knowledge_delta??{}) as {discovered_nodes?:string[];observed_edges?:string[][];access_changes?:string[][]};
    const ids=[row.source_node,row.target,...(delta.discovered_nodes??[])];
    for(const [source,target,type] of delta.observed_edges??[]){
      if(valid(source)&&valid(target)){observed.push({source,target,type});ids.push(source,target);}
    }
    for(const [id,level] of delta.access_changes??[]){levels.set(id,level);ids.push(id);}
    for(const id of ids.filter(valid)){known.add(id);if(!first.has(id))first.set(id,Number(row.step));}
    if(row.success===true && valid(row.target))targets.add(row.target);
  }
  const edges:Edge[]=assessment?(limited?observed:configured):data.edges;
  const available=nodes.filter(n=>!limited || known.has(n.id));
  const byId=new Map(available.map(n=>[n.id,n]));
  const zones=available.filter(n=>["network_segment","segment","zone"].includes(n.type.toLowerCase()));
  const hosts=available.filter(n=>n.type.toLowerCase()==="host");
  const memberships=new Map(edges.filter(e=>e.type.toLowerCase()==="located_in").map(e=>[e.source,e.target]));
  const crowns=new Set((assessment?.topology.crown_jewels as string[]|undefined)??available.filter(n=>n.attributes.objective===true).map(n=>n.id));
  const entry=available.filter(n=>n.type.toLowerCase()==="entry_point");
  const node=byId.get(selected),spec=assessment?.specification;
  const pick=(id:string)=>{setSelected(id);setRelation(null);setExpanded(expanded===id?"":id);};
  const chip=(n:Node)=> <button key={n.id} type="button" className={["zone-chip",combined&&targets.has(n.id)?"progressed":"",crowns.has(n.id)?"crown":""].join(" ")} onClick={()=>pick(n.id)}>
    {crowns.has(n.id)?"★ ":""}{n.type==="entry_point"?"Assessment Entry":n.name}<small>{n.id}</small></button>;
  const changeStep=(n:number)=>{setCount(n);setSelected("");setRelation(null);setExpanded("");};
  const last=history.at(-1);
  const accessEdges=edges.filter(e=>accessTypes.has(e.type.toLowerCase()));
  const observedAccess=assessment&&!limited?observed.filter(e=>accessTypes.has(e.type.toLowerCase())):[];
  const basisFor=(edge:Edge)=>{
    if(assessment)return limited?"Observed":"Configured";
    const fact=data.edges.find(e=>e===edge);
    const status=String(fact?.metadata.evidence_status??fact?.metadata.status??"").toLowerCase();
    if(status==="inferred"||status==="derived")return "Derived";
    if(status==="configured")return "Configured";
    return fact?.evidence_refs.length?"Recorded relationship":"Unknown";
  };
  const hostFor=(id:string)=> {
    const visited=new Set<string>(),queue=[id];
    while(queue.length){
      const next=queue.shift()!;
      if(visited.has(next))continue;
      visited.add(next);
      if(memberships.has(next))return next;
      queue.push(...edges.filter(e=>e.target===next&&children.has(e.type.toLowerCase())).map(e=>e.source));
    }
    return undefined;
  };
  const stageRows=history.filter((r,i,a)=>r.success===true&&(a.findIndex(x=>x.success===true&&x.action_kind===r.action_kind)===i||r.goal_reached===true||i===a.length-1));
  const reached=history.some(r=>r.goal_reached===true);
  const stageLink=(row:Fact)=>{
    const source=valid(row.source_node)?row.source_node:null;
    return <button className={row.success===false?"zone-stage-link unsuccessful":"zone-stage-link"} key={String(row.step)} onClick={()=>{setSelected("");setRelation(row);}}>
      {source&&<span>{byId.get(source)?.name??source} → </span>}
      <b>Step {String(row.step)} · {readable(String(row.action_kind))}</b>
      <span> → {byId.get(String(row.target))?.name??String(row.target)}</span>
      <small>{source?"Recorded source and target":"Recorded action target"} · {row.success===true?"Succeeded":row.success===false?"Failed":unknown}</small>
    </button>;
  };
  const displayEdge=(e:Edge,basis:string,i:number)=><button key={i} onClick={()=>{
    const saved=data.edges.find(r=>r.source===e.source&&r.target===e.target&&r.type===e.type);
    const earliest=history.find(row=>((row.knowledge_delta as {observed_edges?:string[][]})?.observed_edges??[]).some(([a,b,t])=>a===e.source&&b===e.target&&t===e.type));
    setSelected("");setRelation({from:e.source,to:e.target,relationship:e.type,basis,step:earliest?.step??(!limited?saved?.metadata.step:undefined),evidence_id:earliest?.evidence_id??(!limited?saved?.evidence_refs.join(", "):undefined)});
  }}>{e.source} → {e.target} · {readable(e.type)} · {basis}</button>;
  const inspectHosts=hosts.filter(n=>memberships.get(n.id)===selected);
  const services=edges.filter(e=>e.source===selected&&children.has(e.type.toLowerCase())).map(e=>byId.get(e.target)).filter((n):n is Node=>!!n);
  const currentAccess=levels.get(selected)??(!limited?node?.attributes.current_access_level:undefined);
  return <section className="enterprise-structure"><h3>Enterprise Topology Structure</h3>
    <p>Zone membership describes logical organisation. Lines of access appear only for recorded or configured relationships.</p>
    {combined&&episode&&<div className="zone-tools">
      <label>Episode <select value={index} onChange={e=>{setPlaying(false);setIndex(Number(e.target.value));changeStep(0);}}>{assessment!.episodes.map((_,i)=><option key={i} value={i}>{i+1}</option>)}</select></label>
      <label><input type="checkbox" checked={playback} onChange={e=>{setPlayback(e.target.checked);changeStep(0);}}/> Step through observed topology</label>
      {limited&&<><button disabled={next==null} onClick={()=>setPlaying(!playing)}>{playing?"Pause":"Play"}</button><button disabled={!count} onClick={()=>changeStep(prev)}>Previous step</button><button disabled={next==null} onClick={()=>changeStep(next??count)}>Next step</button><label>Jump to step <select value={count} onChange={e=>changeStep(Number(e.target.value))}><option value={0}>Entry</option>{stops.map(n=><option key={n} value={n}>Step {String(events[n-1].step)}</option>)}</select></label><label><input type="checkbox" checked={showFailures} onChange={e=>{setShowFailures(e.target.checked);changeStep(0);}}/> Show failures</label></>}
    </div>}
    <div className="zone-tools"><button onClick={()=>setAllServices(!allServices)}>{allServices?"Collapse services":"Expand services"}</button><label><input type="checkbox" checked={access} onChange={e=>setAccess(e.target.checked)}/> Show access / reachability</label>
    <label><input type="checkbox" checked={controls} onChange={e=>setControls(e.target.checked)}/> Security boundaries</label></div>
    {controls&&<Fields value={spec?.controls??{controls:unknown}}/>}
    <div className="zone-tools">{entry.map(chip)}{available.filter(n=>crowns.has(n.id)).map(chip)}
    {available.some(n=>crowns.has(n.id))&&<span>{!episode?unknown:limited&&!reached?"Objective pending":reached?"Objective reached":"Objective not reached"}</span>}</div>
    <div className="zone-grid">{[...zones.map(n=>({id:n.id,name:n.name})),{id:"",name:"Membership unavailable"}].map(z=>{
      const members=hosts.filter(h=>(memberships.get(h.id)??"")===z.id);
      if(!members.length&&!z.id)return null;
      return <section className="zone-card" key={z.id}><h4>{z.id?<button onClick={()=>pick(z.id)}>{z.name}</button>:z.name}</h4>
        <div>{members.map(chip)}</div>
        {allServices&&members.map(host=>{
          const attached=edges.filter(e=>e.source===host.id&&e.type.toLowerCase()==="hosts").map(e=>byId.get(e.target)).filter((n):n is Node=>n?.type==="service");
          return attached.length?<div key={host.id}><small>{host.name}</small>{attached.map(chip)}</div>:null;
        })}
        {available.filter(n=>crowns.has(n.id)&&memberships.get(hostFor(n.id)??"")===z.id).map(chip)}
        {combined&&<div className="zone-stages">{(limited&&last?[last]:stageRows).filter(r=>memberships.get(hostFor(String(r.target))??hostFor(String(r.source_node))??"")===z.id && z.id).map(stageLink)}</div>}</section>;
    })}</div>
    {combined&&<details open={limited}><summary>Recorded progression</summary>
      {assessment?(limited?(last?[last]:[]):stageRows).map(stageLink):projectedStages.length?projectedStages.map(e=><button key={e.id} onClick={()=>{setSelected("");setRelation({...e.metadata,from:e.source,to:e.target,relationship:e.type,basis:"Recorded projection",evidence_id:e.evidence_refs.join(", ")});}}>Step {String(e.metadata.step)} · {readable(e.type)} → {e.target}</button>):<p>No progression recorded in this selection.</p>}
    </details>}
    {access&&<details open><summary>Access relationships</summary>{accessEdges.map((e,i)=>displayEdge(e,basisFor(e),i))}
    {observedAccess.map((e,i)=>displayEdge(e,"Observed",i+edges.length))}
    {!accessEdges.length&&!observedAccess.length&&<p>Reachability not established in this selection.</p>}</details>}
    <details open className="topology-profile"><summary>Topology Profile</summary><Fields value={{topology_class:!limited&&zones.length>1&&spec?.controls?.firewall_segmentation===true?"Segmented enterprise logical topology":zones.length?"Enterprise logical zones":"Zone structure unavailable",environment:spec?.organisation_type??unknown,
      systems:hosts.length,logical_zones:zones.length,entry_context:entry.map(n=>n.name).join(", ")||unknown,critical_asset:available.filter(n=>crowns.has(n.id)).map(n=>n.name).join(", ")||unknown,
      segmentation:spec?.segmentation??unknown,physical_topology:"Not explicitly modelled",logical_topology:limited?"Recorded through selected step":assessment?"Configured inventory":"Available projection only"}}/></details>
    {node&&<aside><h4>{node.name}</h4><Fields value={{identifier:node.id,type:node.type,segment:byId.get(memberships.get(hostFor(node.id)??"")??"")?.name??unknown,role:node.attributes.role??unknown,criticality:node.attributes.criticality??unknown,internet_exposure:node.attributes.internet_exposed??unknown,
      observed_at_step:first.get(selected)??node.attributes.first_discovery_step??unknown,access:currentAccess??unknown,successful_action_target:combined?targets.has(selected):unknown,
      ...(zones.some(z=>z.id===selected)?{hosts:inspectHosts.length,device_types:[...new Set(inspectHosts.map(n=>n.attributes.category))],purpose:node.attributes.role??unknown,critical_assets:available.filter(n=>crowns.has(n.id)&&memberships.get(hostFor(n.id)??"")===selected).map(n=>n.name),discovered:first.has(selected)?"Recorded":unknown,reachability:accessEdges.filter(e=>e.source===selected||e.target===selected).map(e=>e.type)}:{}),
      observed_findings:history.filter(r=>r.success===true&&r.action_kind==="assess_vulnerability"&&r.target===selected).map(r=>r.simulator_vulnerability_id).filter(valid),evidence_basis:assessment?(limited?"Recorded presence; labels from configuration":"Configured scenario"):"Neo4j projection"}}/>
      {expanded===selected&&services.length>0&&<div>Hosted entities {services.map(chip)}</div>}
      <details><summary>Technical provenance</summary><Fields value={{graph_id:data.graph_id,node_metadata:node.attributes}}/></details></aside>}
    {relation&&<aside><h4>Relationship / action evidence</h4><Fields value={Object.fromEntries(Object.entries(relation).filter(([k])=>["from","to","relationship","basis","step","action_kind","target","success","state_changed","source_node"].includes(k)))}/><Mappings value={relation.mitre_mappings}/><details><summary>Technical provenance</summary>{String(relation.evidence_id??data.graph_id??unknown)}</details></aside>}
    <small>Legend · Zone = segment · Host = system · Hosted entities = service or identity · Assessment Entry = simulator entry · ★ = critical asset. Zone cards show membership. Action arrows link recorded sources, events and targets. Milestones appear in time order. Select a host for services and identity context. ★ Critical asset · Green outline: successful action target.</small>
  </section>;
}
