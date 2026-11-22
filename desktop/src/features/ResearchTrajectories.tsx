import {RegisteredJourney,type Journey} from "./RegisteredJourney";
import { Badge } from "../components/EvidenceDisplay";
import { useEffect, useState } from "react";
import { downloadReport, get } from "../api/client";

export interface ResearchEpisodeChoice {topology_seed:number;topology_hash:string;evaluation_episode_seed:number;episode_length:number}
export interface ResearchPolicyChoice {training_seed:number;status:string;policy_sha256?:string;checkpoint_sha256?:string;episodes:ResearchEpisodeChoice[]}
type Value=string|number|boolean|null|undefined|object;
export interface ResearchTrajectory {
 journey?:Journey;topology_context?:{registered_limits:object;structure_status:string;limit_source:string;target_ids:string[]};
 label:string;explanation:string;identity:Record<string,Value>;episode:Record<string,Value>;
 summary:{start:string;major_stages:{category:string;first_step:number;last_step:number}[];notable_actions:string[];notable_rule:string;
  objective_reached:boolean;final_action:string;total_steps:number;total_return:number;terminal_outcome:string;mitre_techniques:Record<string,Value>[]};
 steps:{recorded:Record<string,Value>;source_line:number}[];
 chronology:{meaning:string;relationship:string;links:{from_step:number;to_step:number}[]};
 evidence_availability:Record<string,string>;limitations:string[];provenance:Record<string,Value>;
}
const explanation="This viewer reconstructs recorded PPO validation actions from frozen research evidence. Chronological links do not imply host-to-host network connectivity unless explicitly present in the source evidence.";
const label="REGISTERED PPO VALIDATION EVIDENCE — READ-ONLY RECONSTRUCTION";
const value=(v:Value)=>v==null?"Not recorded":typeof v==="object"?JSON.stringify(v):String(v);
export function ResearchTrajectories({token}:{token:string}) {
 const [policies,setPolicies]=useState<ResearchPolicyChoice[]>([]),[loadingIndex,setLoadingIndex]=useState(true),[indexError,setIndexError]=useState("");
 const [selection,setSelection]=useState<{policy:number;topology:number;evaluation:number}|null>(null);
 const [data,setData]=useState<ResearchTrajectory|null>(null),[error,setError]=useState(""),[report,setReport]=useState(false),[exporting,setExporting]=useState(false);
 useEffect(()=>{const abort=new AbortController();setPolicies([]);setSelection(null);setData(null);setLoadingIndex(true);setIndexError("");
  get<{policies:ResearchPolicyChoice[]}>("research/ppo-trajectories",token,abort.signal).then(result=>{
   if(abort.signal.aborted)return;setPolicies(result.policies);
   const first=result.policies.find(p=>p.status==="AVAILABLE"&&p.episodes.length);
   if(first)setSelection({policy:first.training_seed,topology:first.episodes[0].topology_seed,evaluation:first.episodes[0].evaluation_episode_seed});
  }).catch(e=>{if(!abort.signal.aborted)setIndexError(String(e));}).finally(()=>{if(!abort.signal.aborted)setLoadingIndex(false);});
  return()=>abort.abort();},[token]);
 const path=selection?`research/ppo-trajectories/${selection.policy}/${selection.topology}/${selection.evaluation}`:"";
 useEffect(()=>{setData(null);setError("");setReport(false);if(!path)return;const abort=new AbortController();
  get<ResearchTrajectory>(path,token,abort.signal).then(result=>{if(!abort.signal.aborted)setData(result);}).catch(e=>{if(!abort.signal.aborted)setError(String(e));});
  return()=>abort.abort();},[path,token]);
 const policy=policies.find(p=>p.training_seed===selection?.policy);
 const topologies=Array.from(new Set(policy?.episodes.map(e=>e.topology_seed)??[]));
 const episodes=policy?.episodes.filter(e=>e.topology_seed===selection?.topology)??[];
 function select(policy:number,episode:ResearchEpisodeChoice){setData(null);setReport(false);setSelection({policy,topology:episode.topology_seed,evaluation:episode.evaluation_episode_seed});}
 const [saved,setSaved]=useState("");
 async function exportReport(format:string){if(!selection||!data)return;setExporting(true);setError("");try{
  setSaved("");const destination=await downloadReport(`${path}/export/${format}`,token,`research-ppo-${selection.policy}-${selection.topology}-${selection.evaluation}.${format}`);if(destination)setSaved("Saved to "+destination);
 }catch(e){setError(String(e));}finally{setExporting(false);}}

 return <section aria-label="PPO trajectories">
  <header className="simulation-banner"><h2>PPO Trajectories</h2><strong>{label}</strong><p>{explanation}</p></header>
  <p>Frozen validation records only. No model execution, database import or engineering conversion. Missing evidence stays Not recorded.</p>
  {loadingIndex&&<p role="status">Loading registered episode index…</p>}
  {indexError&&<p role="alert">Research trajectories unavailable: {indexError}</p>}
  {!loadingIndex&&!indexError&&!policies.some(p=>p.status==="AVAILABLE"&&p.episodes.length)&&<p>No recorded validation episodes available. No substitute trajectory is displayed.</p>}
  {policies.length>0&&<div className="wizard-grid">
   <label>Training seed / policy<select value={selection?.policy??""} onChange={e=>{const p=policies.find(p=>p.training_seed===Number(e.target.value));if(p?.episodes[0])select(p.training_seed,p.episodes[0]);}}>
    {!selection&&<option value="">Select an available policy</option>}{policies.map(p=><option key={p.training_seed} value={p.training_seed} disabled={p.status!=="AVAILABLE"||!p.episodes.length}>Policy seed {p.training_seed}{p.status!=="AVAILABLE"?" — unavailable":""}</option>)}</select></label>
   <label>Validation topology<select value={selection?.topology??""} onChange={e=>{const first=policy?.episodes.find(ep=>ep.topology_seed===Number(e.target.value));if(policy&&first)select(policy.training_seed,first);}}>{topologies.map(t=><option key={t} value={t}>{t}</option>)}</select></label>
   <label>Evaluation episode seed<select value={selection?.evaluation??""} onChange={e=>{const ep=episodes.find(ep=>ep.evaluation_episode_seed===Number(e.target.value));if(policy&&ep)select(policy.training_seed,ep);}}>{episodes.map(e=><option key={e.evaluation_episode_seed} value={e.evaluation_episode_seed}>{e.evaluation_episode_seed}</option>)}</select></label>
  </div>}
  {saved&&<p role="status">{saved}</p>}{error&&<p role="alert">Recorded trajectory unavailable: {error}</p>}
  {selection&&!data&&!error&&<p role="status">Loading selected frozen episode…</p>}
  {data&&<>
   <details><summary>Episode / policy / topology identity</summary><dl>{Object.entries(data.identity).map(([k,v])=><div key={k}><dt>{k.replaceAll("_"," ")}</dt><dd className="hash">{value(v)}</dd></div>)}</dl></details>
   <section aria-label="Recorded trajectory summary"><h3>PPO Contribution in This Episode</h3>
    <p>The frozen policy selected {data.summary.total_steps} recorded actions and {data.summary.objective_reached?"reached":"did not reach"} the synthetic objective on this validation topology.</p>
    <p>Successful recorded actions: {data.steps.filter(s=>s.recorded.success===true).length} · Distinct action categories: {new Set(data.steps.map(s=>s.recorded.action_kind)).size} · Final reward: {String(data.steps.at(-1)?.recorded.reward ?? "Not recorded")}</p>
    <dl className="summary-strip">{[["Policy seed",selection?.policy],["Topology seed",selection?.topology],["Evaluation seed",selection?.evaluation],["Total steps",data.summary.total_steps],["Total return",data.summary.total_return]].map(([k,v])=><div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}</dl>
    <Badge>{data.summary.objective_reached?"Objective reached":"Objective not reached"}</Badge> <Badge>Read only</Badge> <Badge>Frozen evidence</Badge>
    <p>Episode started: {data.summary.start}</p>
    <p>Final action: {data.summary.final_action}</p><p>Terminal outcome: {data.summary.terminal_outcome}</p>
   </section>
   <RegisteredJourney key={path} data={data}/>
   <details><summary>Evidence not captured in the original validation run</summary><dl>{Object.entries(data.evidence_availability).map(([k,v])=><div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}</dl><p>These fields were not preserved in the frozen validation records and are intentionally not inferred.</p></details>
   <h3>Evidence limitations</h3><ul>{data.limitations.map(line=><li key={line}>{line}</li>)}</ul>
   <details><summary>Source provenance / hashes</summary><pre>{JSON.stringify(data.provenance,null,2)}</pre></details>
   <button onClick={()=>setReport(true)}>Generate Research Trajectory Report</button>
   {report&&<section aria-label="Research trajectory report"><h3>Research Trajectory Report</h3><p>{data.label}</p><p>Rendered from the selected frozen episode. Generation is read-only and does not save evidence into a database.</p>
    <div className="simulation-tabs">{([['html','Download HTML'],['pdf','Download PDF'],['json','Export JSON']] as const).map(([format,label])=><button disabled={exporting} key={format} onClick={()=>void exportReport(format)}>{label}</button>)}</div>
   </section>}
  </>}
 </section>;
}
