import {useEffect,useState} from "react";
import type {Fact} from "../types";
import {Fields,Mappings} from "../components/EvidenceDisplay";

export function revealed(row:Fact):string[] {
 const delta=row.knowledge_delta as {discovered_nodes?:string[]}|undefined;
 return [...new Set(delta?.discovered_nodes ?? [])];
}
export function ProgressivePath({events,entry,ppo=false}:{events:Fact[];entry?:string;ppo?:boolean}) {
 const [cursor,setCursor]=useState(-1),[playing,setPlaying]=useState(false),[all,setAll]=useState(false);
 const [selected,setSelected]=useState<number|null>(null);
 useEffect(()=>{setCursor(-1);setSelected(null);setPlaying(false);},[events]);
 useEffect(()=>{
  if(!playing)return;
  const timer=setInterval(()=>setCursor(n=>{if(n>=events.length-1){setPlaying(false);return n;}return n+1;}),700);
  return ()=>clearInterval(timer);
 },[playing,events.length]);
 const history=events.slice(0,cursor+1);
 const visible=history.map((row,index)=>({row,index})).filter(({row})=>all || row.success===true&&(row.state_changed===true||revealed(row).length>0||row.goal_reached===true));
 const row=selected===null?undefined:events[selected];
 return <section aria-label="Progressive Attack Path">
  <h3>{ppo?"Chronological PPO Progression":"Progressive Attack Path"}</h3>
  <p>{ppo?"Chronological PPO validation trajectory — not necessarily literal network connectivity. Complete host-to-host reconstruction is unavailable from the retained validation evidence.":"Recorded assessment progression. Action cards link recorded sources to their outcomes; adjacent cards indicate time order."}</p>
  <div className="playback-controls">
   <button disabled={cursor<0} onClick={()=>setCursor(n=>n-1)}>Previous step</button>
   <button disabled={cursor>=events.length-1} onClick={()=>setCursor(n=>n+1)}>Next step</button>
   <button onClick={()=>setPlaying(v=>!v)}>{playing?"Pause":"Play"}</button>
   <label>Jump to step<input type="number" min={-1} max={events.length-1} value={cursor} onChange={e=>{setPlaying(false);setCursor(Math.max(-1,Math.min(events.length-1,Number(e.target.value))));}}/></label>
   <label><input type="checkbox" checked={all} onChange={e=>setAll(e.target.checked)}/>Show failed/non-progressing actions</label>
  </div>
  <div className="objective-result">{entry ?? "Entry identity not recorded"}</div>
  <ol className="journey-ranges">{visible.map(({row:r,index})=><li key={index}>
   <button aria-pressed={selected===index} onClick={()=>setSelected(index)}>
    Step {String(r.step)} · {ppo?"PPO selected ":""}{String(r.action_kind ?? r.simulator_action ?? "Not recorded").replaceAll("_"," ")}
    <span>Target · {String(r.target ?? r.target_entity ?? "Not recorded")} · Reward {String(r.reward ?? "Not recorded")}</span>
    <span>{r.goal_reached===true?"Objective reached":r.success===false?"Failed attempt":r.state_changed===true?"Recorded state change":"No recorded state change"}</span>
   </button>
   <p>Recorded source · {String(r.source_node && r.source_node!=="UNKNOWN"?r.source_node:"Unknown recorded source")}</p>
   <div className="journey-targets">{revealed(r).map(id=><button key={id} onClick={()=>{setCursor(index);setSelected(index);}} title={"Added at step "+r.step+" by "+r.action_kind}>{id}</button>)}</div>
  </li>)}</ol>
  {row&&<aside className="details"><h4>Why did the view expand?</h4><p>Step {String(row.step)} recorded {String(row.action_kind)} with success {String(row.success)} and state change {String(row.state_changed)}.</p><Mappings value={row.framework_mappings ?? row.mitre_mappings}/><Fields value={{target:row.target ?? row.target_entity,revealed_entities:revealed(row),reward:row.reward,evidence:row.evidence_id}}/><details><summary>Technical provenance</summary><Fields value={row}/></details></aside>}
  {cursor===events.length-1&&<section className="notice"><h4>What happened</h4><p>{events.length} recorded steps · {history.filter(r=>r.success===true&&r.state_changed===true).length} successful state-changing actions · {new Set(history.flatMap(revealed)).size} revealed entities.</p><p>{history.some(r=>r.goal_reached===true)?"Objective reached":"Objective unreached. Recorded progression ended here."} Final target · {String(events.at(-1)?.target ?? events.at(-1)?.target_entity ?? "Not recorded")}</p></section>}
 </section>;
}
