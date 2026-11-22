import {EpisodePlayback} from "./EpisodePlayback";
import {ProgressivePath} from "./ProgressivePath";
import {useState} from "react";
import {Badge, Fields, Mappings} from "../components/EvidenceDisplay";
import type {ResearchTrajectory} from "./ResearchTrajectories";

export interface Journey {
  groups: {offset:number;first:number;last:number;count:number;successful:number;failed:number;reward:number;targets:string[];techniques:string[];stages:string[]}[];
  notable:Record<string,string[]>;
  review?:Record<string,Record<string,unknown>>;
  stages:string[];
}
type Mode="Episode Simulation"|"Topology"|"RL Attack Journey"|"Combined";

export function RegisteredJourney({data}:{data:ResearchTrajectory}) {
  const [mode,setMode]=useState<Mode|null>(null);
  const [group,setGroup]=useState<number|null>(null);
  const [cursor,setCursor]=useState<number|null>(null);
  const [target,setTarget]=useState("");
  const journey=data.journey, topology=data.topology_context;
  const selected=cursor===null?undefined:data.steps[cursor];
  const row=selected?.recorded;
  const last=data.steps.length-1;
  function inspectStep(index:number) {
    const owner=journey?.groups.findIndex(g=>index>=g.offset && index<g.offset+g.count);
    if(owner===undefined || owner<0)return;
    setGroup(owner);setCursor(index);
  }
  const matches=data.steps.filter(step=>step.recorded.target_entity===target);
  function evidence(){return <><Fields value={data.identity}/><Fields value={data.provenance}/></>;}
  return <section aria-label="Episode exploration">
    <nav className="simulation-tabs" aria-label="Episode view">{(["Topology","Episode Simulation","RL Attack Journey","Combined"] as const).map(v=>
      <button key={v} aria-pressed={mode===v} onClick={()=>{setMode(v);setCursor(null);setGroup(null);setTarget("");}}>{v==="Combined"?v:"View "+v}</button>)}</nav>
    {mode==="Episode Simulation"&&<EpisodePlayback model={{events:data.steps.map(s=>s.recorded),identity:data.identity,registered:true}} data={{source:"engineering-simulation",graph_id:null,nodes:(topology?.target_ids??[]).map(id=>({id,label:id,type:"asset",metadata:{},status:id===data.steps.at(-1)?.recorded.target_entity&&data.summary.objective_reached?"OBJECTIVE":"OBSERVED",provenance:[]})),edges:[]}}/>}
    {mode && <p className="journey-key">Registered PPO trajectory overlay — chronological evidence does not necessarily imply literal network connectivity. Topology identity identifies the evaluated environment. Target chips link exact recorded IDs. Numbered ranges show time order only.</p>}
    {(mode==="Topology"||mode==="Combined")&&<article className="wizard-card">
      <h3>Validation topology {String(data.identity.topology_seed)}</h3>
      <p>Structural snapshot · {topology?.structure_status ?? "Not recorded"}. Subnet membership, hosted services, criticality and network relationships are unavailable.</p>
      <details><summary>Registered generator limits</summary><p>Bounds for the topology distribution.</p><Fields value={topology?.registered_limits}/><small>{topology?.limit_source}</small></details>
      <details><summary>View Evidence</summary>{evidence()}</details>
      <h4>Targets referenced by frozen actions</h4>
      <p>{topology?.target_ids.length??0} recorded target entities</p><div className="journey-targets">{topology?.target_ids.filter(id=>!id.toLowerCase().includes("decoy")).slice(0,12).map(id=><button key={id} aria-pressed={target===id} onClick={()=>setTarget(id)}>{id}</button>)}</div><details><summary>Show all recorded target IDs</summary><div className="journey-targets">{topology?.target_ids.filter(id=>id.toLowerCase().includes("decoy")||topology.target_ids.filter(x=>!x.toLowerCase().includes("decoy")).indexOf(id)>=12).map(id=><button key={id} onClick={()=>setTarget(id)}>{id}</button>)}</div></details>
      {target&&<aside className="details"><h4>{target}</h4><p>Type, segment, criticality and attached services · Not recorded</p>
        <p>Recorded target association · Steps {matches.map(s=>s.recorded.step).join(", ")}</p>
        {mode==="Combined"&&<div className="journey-targets">{matches.map(s=><button key={s.source_line} onClick={()=>inspectStep(data.steps.indexOf(s))}>Inspect step {String(s.recorded.step)}</button>)}</div>}
        <Mappings value={matches.flatMap(s=>Array.isArray(s.recorded.framework_mappings)?s.recorded.framework_mappings:[])}/>
        <details><summary>View Evidence</summary>{evidence()}<Fields value={matches.map(s=>({step:s.recorded.step,line:s.source_line,cve_id:s.recorded.cve_id,cvss_base:s.recorded.cvss_base}))}/></details></aside>}
    </article>}
    {(mode==="RL Attack Journey"||mode==="Combined")&&journey&&<>
      <details><summary>Step-by-step PPO progression</summary><ProgressivePath events={data.steps.map(s=>s.recorded)} ppo/></details>
      <h3>RL Attack Journey</h3><p>Red Team Lifecycle is the project’s analyst-facing grouping. ATT&amp;CK mappings come from each recorded action.</p>
      <div className={selected?"journey-inspection":"journey-overview"}><ol className="journey-ranges">{journey.groups.map((g,i)=><li key={g.offset}>
        <button aria-expanded={group===i} onClick={()=>{setGroup(group===i?null:i);setCursor(null);}}>
          <strong>Steps {g.first}–{g.last}</strong><span>{g.stages.join(" · ")}</span>
          <small>{g.count} actions · {g.successful} successful · {g.failed} failed · Reward {Number(g.reward.toFixed(4))}</small>
        </button>
        <p>Targets · {g.targets.slice(0,3).join(", ") || "Not recorded"}{g.targets.length>3?" and "+(g.targets.length-3)+" more":""} · ATT&amp;CK · {g.techniques.join(", ") || "Not recorded"}</p>
        <small>{data.steps.slice(g.offset,g.offset+g.count).filter(s=>journey.notable[String(s.recorded.step)]).length} notable recorded actions</small>
        {group===i&&<ol aria-label="Chronological PPO trajectory">{data.steps.slice(g.offset,g.offset+g.count).map((s,j)=><li key={s.source_line}>
          <button aria-pressed={cursor===g.offset+j} onClick={()=>setCursor(g.offset+j)}>Step {String(s.recorded.step)} · {String(s.recorded.simulator_action ?? s.recorded.action ?? "Not recorded")}
          {s.recorded.goal_reached===true?" · Objective reached":journey.notable[String(s.recorded.step)]?" · Notable":""}</button></li>)}</ol>}
      </li>)}
        {data.steps[last]?.recorded.goal_reached===true&&<li className="objective-result"><button onClick={()=>inspectStep(last)}>
          <strong>Terminal objective reached</strong><span>{String(data.steps[last].recorded.target_entity ?? "Not recorded")} · Step {String(data.steps[last].recorded.step)}</span></button></li>}
      </ol>
      {selected&&row&&cursor!==null&&<aside className="wizard-card" aria-label="Selected recorded action">
        <h3>{row.goal_reached===true?"Objective reached":"Recorded event"} · Step {String(row.step)}</h3>
        <Badge>Recorded evidence</Badge><p>PPO selected {String(row.simulator_action ?? row.action ?? "Not recorded")}.</p>
        <Fields value={Object.fromEntries(["step","rl_action_index","target_entity","reward","success","goal_reached","state_changed","prerequisites","outcomes"].map(k=>[k,row[k]]))}/>
        <h4>MITRE ATT&amp;CK</h4><Mappings value={row.framework_mappings}/>
        <Badge>Derived interpretation</Badge><p>Red Team Lifecycle · {journey.stages[cursor]}</p>
        {journey.notable[String(row.step)]&&<><h4>Notable recorded PPO action</h4><p>This event matters because the record shows: {journey.notable[String(row.step)].join("; ")}.</p></>}
        <h4>Why could the assessment progress?</h4>{journey.review?.[String(row.step)]&&<Fields value={journey.review[String(row.step)]}/>}<p>{row.success===true?"The simulator recorded a successful action. The listed prerequisites and outcomes are the evidence for this transition.":"This action does not establish successful progression."}</p>
        {row.goal_reached===true&&<section className="objective-result"><h4>Why this matters</h4><p>The simulated objective was reached on {String(row.target_entity ?? "an unrecorded target")}.</p>
        <h4>What could have prevented or limited this path?</h4><p>Review access restrictions on the recorded objective target against this step’s prerequisites. The validation run did not measure whether a control would block it.</p></section>}
        <details><summary>View Evidence</summary><p>{String(data.provenance.trajectory_file)} · line {selected.source_line}</p>{evidence()}
          <details><summary>View original record</summary><pre>{JSON.stringify(row,null,2)}</pre></details></details>
      </aside>}</div>
      <section className="notice"><h3>Reporting &amp; Debrief</h3><p>Post-assessment analyst workflow · Correlate recorded evidence, review findings and implications, discuss controls, then export the stakeholder report.</p></section>
    </>}
  </section>;
}
