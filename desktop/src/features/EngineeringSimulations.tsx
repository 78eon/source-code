import {ProgressivePath} from "./ProgressivePath";
import { Badge, Mappings } from "../components/EvidenceDisplay";
import { useEffect, useRef, useState } from "react";
import { downloadReport, get, post } from "../api/client";
import type { Fact, GraphDTO } from "../types";
import { NewSimulationWizard } from "./NewSimulationWizard";
import { SIMULATION_DISCLAIMER, type SimulationSpec, type SimulationStatus, type ExampleScenario } from "./simulationTypes";
import { GraphWorkspace } from "./topology/GraphWorkspace";
import { RecordBrowser } from "../components/RecordBrowser";
import { ExampleScenarios } from "./ExampleScenarios";
import { DecisionEngine } from "./DecisionEngine";
import { SimulationAssessment } from "./SimulationAssessment";
interface Stored {simulation_id:string; specification:SimulationSpec; specification_sha256:string; topology_sha256:string; created_at:string; topology:Fact; vulnerability_assignments:Fact[]}
interface Result {lineage:Fact[];graph_id:string; report_id:string; episodes:{outcome:string; goal_reached:boolean; environment_return:number; events:Fact[]}[]; report:Fact; graph:Fact}
type Row={simulation_id:string;name:string;seed:number;created_at:string;completed:boolean;topology_sha256?:string};
function SavedInventory({row,token}: {row: Row; token: string}) {
 const [spec,setSpec]=useState<SimulationSpec|null>(null);
 const [objective,setObjective]=useState("Not recorded");
 useEffect(()=>{
   const controller=new AbortController();
   const options=controller.signal;
   get<Stored>(`engineering-simulations/${row.simulation_id}`,token,options)
     .then(r=>{if(!options.aborted)setSpec(r.specification);}).catch(()=>{});
   if(row.completed) get<AssessmentSummary>(`engineering-simulations/${row.simulation_id}/export/json`,token,options)
     .then(r=>{if(!options.aborted && typeof r.summary?.objective_reached==="boolean")setObjective(r.summary.objective_reached?"Reached":"Not reached");}).catch(()=>{});
   return ()=>controller.abort();
 },[row.simulation_id,row.completed,token]);
 return <dl className="summary-strip"><div><dt>Devices</dt><dd>{spec?.hosts ?? "Not available"}</dd></div>
   <div><dt>Subnets</dt><dd>{spec?.subnets?.length ?? "Not available"}</dd></div>
   <div><dt>Decision engine</dt><dd>{spec?.policy_id ?? "Not available"}</dd></div>
   <div><dt>Objective</dt><dd>{objective}</dd></div></dl>;
}
interface AssessmentSummary {summary?: {objective_reached?: boolean}}
export function EngineeringSimulations({token,initialTab="saved",onResearch,onGraph}:{onGraph?:(g:Fact)=>void;onResearch?:()=>void;token:string;initialTab?:"new"|"saved"|"runs"|"examples"}) {
 const [status,setStatus]=useState<SimulationStatus|null>(null),[tab,setTab]=useState(initialTab),[catalogue,setCatalogue]=useState<Fact[]>([]),[rows,setRows]=useState<Row[]>([]);
 const [record,setRecord]=useState<Stored|null>(null),[result,setResult]=useState<Result|null>(null),[error,setError]=useState(""),[busy,setBusy]=useState("");
 const [panel,setPanel]=useState("progress"),[cursor,setCursor]=useState(0),[playing,setPlaying]=useState(false),[graph,setGraph]=useState<GraphDTO|null>(null),[graphFilter,setGraphFilter]=useState("all"),[graphError,setGraphError]=useState("");
 const [examples,setExamples]=useState<ExampleScenario[]>([]),[exampleError,setExampleError]=useState(""),[selectedExample,setSelectedExample]=useState<ExampleScenario|null>(null);
 const [publication,setPublication]=useState<Fact|null>(null);
 const request=useRef<AbortController|null>(null);
 const generation=useRef(0);
 useEffect(()=>setTab(initialTab),[initialTab]);
 useEffect(()=>{
  generation.current++;
  const abort=new AbortController(); request.current?.abort();setStatus(null);setRows([]);setRecord(null);setResult(null);setPublication(null);setError("");setBusy("Loading engineering workspace…");
  (async()=>{try{const s=await get<SimulationStatus>("engineering-simulations/status",token,abort.signal);if(abort.signal.aborted)return;setStatus(s);
   if(s.enabled){const list=await get<{items:Row[]}>("engineering-simulations",token,abort.signal);if(!abort.signal.aborted)setRows(list.items);
    const metadata=await get<{items:Fact[]}>("engineering-simulations/catalogue",token,abort.signal);if(!abort.signal.aborted)setCatalogue(metadata.items);}
  }catch(e){if(!abort.signal.aborted)setError(String(e));}finally{if(!abort.signal.aborted)setBusy("");}})();
  return()=>{abort.abort();request.current?.abort();};
 },[token]);
 useEffect(()=>{setExamples([]);setExampleError("");if(!status?.enabled)return;const abort=new AbortController();
  get<{items:ExampleScenario[]}>("engineering-simulations/examples",token,abort.signal).then(value=>{if(!abort.signal.aborted)setExamples(value.items);}).catch(e=>{if(!abort.signal.aborted)setExampleError(String(e));});
  return()=>abort.abort();},[status?.enabled,token]);
 const timeline: Fact[]=(result?.episodes??[]).flatMap((episode,i)=>episode.events.map(e=>({...e,episode_index:i,outcome:episode.outcome})));
 const selected=timeline[cursor];
 useEffect(()=>{if(!playing)return;const timer=setInterval(()=>setCursor(i=>{if(i>=timeline.length-1){setPlaying(false);return i;}return i+1;}),650);return()=>clearInterval(timer);},[playing,timeline.length]);
 useEffect(()=>{
  setGraph(null);setGraphError("");if(!record||!result)return;
  const abort=new AbortController();
  get<GraphDTO>(`engineering-simulations/${record.simulation_id}/graph?view=${graphFilter}`,token,abort.signal).then(value=>{if(!abort.signal.aborted)setGraph(value);}).catch(e=>{if(!abort.signal.aborted)setGraphError(String(e));});
  return()=>abort.abort();
 },[record?.simulation_id,result?.graph_id,graphFilter,token]);
 async function refresh(){const current=generation.current;try{const list=await get<{items:Row[]}>("engineering-simulations",token);if(current===generation.current)setRows(list.items);}catch(e){if(current===generation.current)setError(String(e));}}
 async function open(id:string,completed:boolean,initialPanel="progress"){generation.current++;request.current?.abort();const controller=new AbortController();request.current=controller;
  setBusy("Loading stored simulation…");setError("");setRecord(null);setResult(null);setPublication(null);setPlaying(false);setCursor(0);setPanel(initialPanel);setTab("runs");
  try{const saved=await get<Stored>(`engineering-simulations/${id}`,token,controller.signal);if(controller.signal.aborted)return;setRecord(saved);
   if(completed){const replay=await get<Result>(`engineering-simulations/${id}/result`,token,controller.signal);if(!controller.signal.aborted)setResult(replay);}
  }catch(e){if(!controller.signal.aborted)setError(String(e));}finally{if(!controller.signal.aborted)setBusy("");}}
 async function run(){if(!record)return;const current=generation.current;setBusy("Running bounded in-memory simulation. Recorded progression will appear when execution completes…");setError("");
  try{const value=await post<Result>(`engineering-simulations/${record.simulation_id}/run`,token,{});if(current!==generation.current)return;setResult(value);setCursor(0);await refresh();}catch(e){if(current===generation.current)setError(String(e));}finally{if(current===generation.current)setBusy("");}}
 async function publish(){if(!record)return;const current=generation.current;setPublication(null);setBusy("Publishing this engineering report through canonical storage and projection…");setError("");try{const value=await post<Fact>(`engineering-simulations/${record.simulation_id}/publish`,token,{});if(current===generation.current)setPublication(value);}catch(e){if(current===generation.current)setError(String(e));}finally{if(current===generation.current)setBusy("");}}
 const [saved,setSaved]=useState("");
 async function exportReport(format:string){if(!record)return;setError("");try{setSaved("");const destination=await downloadReport(`engineering-simulations/${record.simulation_id}/export/${format}`,token,`${record.simulation_id}.${format}`);if(destination)setSaved("Saved to "+destination);}catch(e){setError(String(e));}}
 return <section className="simulation-workspace" aria-label="Engineering simulations">
  <div className="simulation-banner"><p className="eyebrow">ENGINEERING / NOT REGISTERED RESEARCH</p><strong>{SIMULATION_DISCLAIMER}</strong><p>Synthetic topology → observed decisions → recorded evidence → canonical graph → assessment report.</p></div>
  <div className="simulation-tabs">{([['examples','Example Scenarios'],['new','New Simulation'],['saved','Saved Simulations'],['runs','Simulation Runs']] as const).map(([key,label])=><button key={key} aria-pressed={tab===key} onClick={()=>setTab(key)}>{label}</button>)}</div>
  {busy&&<p role="status">{busy}</p>}{saved&&<p role="status">{saved}</p>}{error&&<p role="alert">{error}</p>}
  {status&&!status.enabled&&<p>Engineering simulation runtime unavailable in this deployment. No substitute results are displayed.</p>}
  {status?.enabled&&(tab==="examples"||tab==="new")&&exampleError&&<p role="alert">Examples unavailable: {exampleError}</p>}
  {status?.enabled&&tab==="examples"&&(examples.length?<ExampleScenarios items={examples} onUse={example=>{setSelectedExample(example);setTab("new");}}/>:!exampleError&&<p role="status">Loading example scenarios…</p>)}
  {status?.enabled&&tab==="new"&&<NewSimulationWizard examples={examples} initialExample={selectedExample} token={token} status={status} catalogue={catalogue} onCreated={id=>{void open(id,false);void refresh();}}/>}
  {status?.enabled&&tab==="saved"&&<><h2>Saved engineering assessments</h2><button disabled={Boolean(busy)} onClick={()=>void refresh()}>Refresh saved simulations</button><p>Immutable specifications and recorded runs. No registered policies or results are imported.</p>{!rows.length&&!busy&&<p>No saved engineering simulations. Choose New Simulation to create one explicitly.</p>}
   <div className="simulation-library">{rows.map(row=><article className="wizard-card" key={row.simulation_id}><p className="eyebrow">{row.completed?"RECORDED RUN":"SPECIFICATION READY"}</p><h3>{row.name}</h3><SavedInventory row={row} token={token}/><p>Seed {row.seed} · {new Date(row.created_at).toLocaleString()}</p><details><summary>Technical details</summary><p className="hash">{row.simulation_id}</p>{row.topology_sha256&&<p className="hash">{row.topology_sha256}</p>}</details><button onClick={()=>void open(row.simulation_id,row.completed)}>Open assessment</button> {row.completed&&<button onClick={()=>void open(row.simulation_id,true,"report")}>Report</button>}</article>)}</div></>}
  {status?.enabled&&tab==="runs"&&!record&&!busy&&<p>Select a saved simulation or create a new specification.</p>}
  {status?.enabled&&tab==="runs"&&record&&<><div className="wizard-heading"><div><p className="eyebrow">SIMULATION RUN</p><h2>{record.specification.name}</h2><p className="hash">{record.simulation_id}</p></div><button disabled={Boolean(busy)||Boolean(result)} onClick={()=>void run()}>{result?"Recorded run complete":"Run Simulation"}</button></div>
   <DecisionEngine/><p>PPO policy binding: Not available for this arbitrary topology. Registered policies require the observation and action contract used in training.</p>{onResearch&&<button onClick={onResearch}>View PPO research evidence</button>}<p>Seed {record.specification.seed} · {record.specification.hosts} hosts · {record.specification.max_steps} maximum steps / episode · {record.specification.episodes} episodes</p>
   <details><summary>Immutable configuration / topology provenance</summary><pre>{JSON.stringify({specification_sha256:record.specification_sha256,topology_sha256:record.topology_sha256,specification:record.specification},null,2)}</pre></details>
   {!result&&!busy&&<p>No simulation results yet. Run Simulation executes only the existing in-memory enterprise environment.</p>}
   {result&&<><div className="simulation-tabs">{[['progressive','Progressive Attack Path'],['progress','Progression'],['graph','Attack / Provenance Graph'],['explain','Explainable Decisions'],['report','Assessment Report']].map(([key,label])=><button key={key} aria-pressed={panel===key} onClick={()=>setPanel(key)}>{label}</button>)}</div>
    {panel==="progressive"&&result.episodes.map((ep,i)=><ProgressivePath key={i} events={ep.events} entry={((record.topology.entry_points ?? []) as string[])[0]}/>)}
    {panel==="progress"&&<><p>Recorded playback after execution — these are actual stored simulator events.</p><div className="cards">{result.episodes.map((episode,i)=><section className="card" key={i}><h3>Episode {i+1}</h3><strong>{episode.outcome}</strong><p>{episode.events.length} steps · Environment return {episode.environment_return}</p></section>)}</div>
     <div className="playback-controls"><button disabled={cursor<=0} onClick={()=>setCursor(i=>i-1)}>Previous step</button><button disabled={!timeline.length} onClick={()=>setPlaying(v=>!v)}>{playing?"Pause playback":"Play recorded progression"}</button><button disabled={cursor>=timeline.length-1} onClick={()=>setCursor(i=>i+1)}>Next step</button><span>Recorded event {timeline.length?cursor+1:0} / {timeline.length}</span></div>
     {selected&&<div className="wizard-card"><h3>Episode {Number(selected.episode_index)+1} · Step {Number(selected.step)+1}</h3><dl><dt>Simulated action</dt><dd>{String(selected.action_kind)}</dd><dt>Source / target</dt><dd>{String(selected.source_node)} → {String(selected.target)}</dd><dt>Simulated result</dt><dd>{String(selected.success)} · {String(selected.outcome)}</dd><dt>Reward</dt><dd>{String(selected.reward)}</dd><dt>Objective observed</dt><dd>{String(selected.goal_reached)}</dd><dt>Evidence ID</dt><dd className="hash">{String(selected.evidence_id)}</dd><dt>MITRE mapping</dt><dd><Mappings value={selected.mitre_mappings}/></dd></dl><details><summary>Recorded state transition and reward contribution</summary><pre>{JSON.stringify({knowledge_delta:selected.knowledge_delta,reward_attribution:selected.reward_attribution},null,2)}</pre></details></div>}</>}
    {panel==="graph"&&<><label>Recorded graph filter<select value={graphFilter} onChange={e=>setGraphFilter(e.target.value)}>{[['all','All discovered nodes'],['attack','Attack path only (recorded back-chain)'],['evidence','Evidence'],['vulnerabilities','Vulnerability transitions'],['mitre','MITRE techniques'],['successful','Successful actions'],['failed','Failed actions']].map(([v,label])=><option key={v} value={v}>{label}</option>)}</select></label>{graphError?<p role="alert">{graphError}</p>:graph?<GraphWorkspace data={graph} assessment={{topology:record.topology,specification:record.specification,episodes:result.episodes,identity:{simulation_id:record.simulation_id,graph_id:result.graph_id,report_id:result.report_id,runs:result.lineage}}}/>:<p role="status">Loading recorded graph…</p>}<button disabled={Boolean(busy)} onClick={()=>void publish()}>Publish canonical evidence and Neo4j projection</button><p>Explicit engineering publication uses canonical ingestion, approval and rebuild. It never selects or approves registered research.</p>{publication&&<div className="notice"><h3>{String(publication.state)}</h3><p>{String(publication.assessment)} · {String(publication.freshness)} · {String((publication.counts as Fact)?.nodes)} nodes · {String((publication.counts as Fact)?.edges)} relationships</p><p>Projected {String(publication.projected_at)}</p><p>Selected graph: {String(publication.graph_id)}</p>{onGraph&&<button onClick={()=>onGraph(publication)}>Open selected Neo4j graph</button>}<p>Selectable report ID: <span className="hash">{String(publication.report_id)}</span></p><p>Copy this ID into Settings → Approved report IDs to use the existing analyst workspace.</p></div>}</>}
    {panel==="explain"&&<><h3>Recorded decision evidence</h3><p>Scores are heuristic ranking values, not probabilities. Empty provenance and unavailable context are not filled in.</p><RecordBrowser rows={timeline} columns={['episode_index','step','action_kind','target','success','reward','evidence_id']}/>{selected&&<><h3>Selected playback event explanation</h3><pre>{JSON.stringify(selected.decision??"Not available from recorded simulation evidence",null,2)}</pre><h3>Security context</h3><pre>{JSON.stringify(selected.catalogue_context??"Not available from recorded simulation evidence",null,2)}</pre></>}</>}
    {panel==="report"&&<><Badge>Engineering simulation</Badge><p>{new Date(record.created_at).toLocaleString()}</p><h3>Simulated Enterprise Penetration Testing Assessment</h3><p>Exports are rendered by the backend from stored engineering evidence. No live exploitation, real-world applicability claim or registered result is included.</p><div className="simulation-tabs"><button onClick={()=>void exportReport('pdf')}>Download PDF</button><button onClick={()=>void exportReport('html')}>Download HTML</button><button onClick={()=>void exportReport('json')}>Export JSON</button></div><p className="hash">Report {result.report_id}</p><SimulationAssessment id={record.simulation_id} token={token}/><details><summary>Configured vulnerability inventory (includes unobserved assignments)</summary><RecordBrowser rows={record.vulnerability_assignments} columns={['id','host','service','cvss','score_source','cve_id','applicability']}/><p>This inventory includes configured assignments. Exports include findings only when a simulated assessment observed them.</p></details><div className="simulation-tabs">{["pdf","html","json"].map(format=><button key={format} aria-label={"Save assessment as "+format.toUpperCase()} onClick={()=>void exportReport(format as "pdf"|"html"|"json")}>{format==="json"?"Export JSON":"Download "+format.toUpperCase()}</button>)}</div></>}
   </>}
  </>}
 </section>;
}
