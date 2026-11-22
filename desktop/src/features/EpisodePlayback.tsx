import {useEffect,useMemo,useState} from "react";
import type {Fact,GraphDTO} from "../types";
import {Badge,Fields,Mappings} from "../components/EvidenceDisplay";
import {episodeState} from "./episodeState";
import {IconGraph} from "./topology/IconGraph";
import type {AssessmentTopology} from "./topology/EnterpriseStructure";

export interface EpisodePlaybackModel {identity:Fact;events:readonly Fact[];registered:boolean}
export function playbackEvent(row:Fact,index:number):Fact{
 const source=row.source_node;
 return {...row,order:index,source:typeof source==="string"&&source!=="UNKNOWN"?source:"Not recorded",
 target:row.target_entity??row.target??"Not recorded",detection:row.detection_event??row.detected??"Not recorded"};
}
const plain=(value:unknown)=>typeof value==="string"?value.replaceAll("_"," "):"Not recorded";
const outcome=(value:unknown)=>value===true?"Success":value===false?"Failed":"Not recorded";
const yesNo=(value:unknown)=>value===true?"Yes":value===false?"No":"Not recorded";
export function milestoneLabel(row:Fact){
 if(row.goal_reached===true)return "Objective reached";
 if(row.detection===true||row.detection_event)return "Detection";
 const kind=String(row.action_kind??"");
 if(/discover/.test(kind))return "Discovery";
 if(/enumerate/.test(kind))return "Enumeration";
 if(/credential/.test(kind))return "Credential acquisition";
 if(/pivot/.test(kind))return "Pivot";
 if(/access|exploit|privilege/.test(kind))return "Access / exploit";
 return undefined;
}
export function EpisodePlayback({model,data,assessment}:{model:EpisodePlaybackModel;data:GraphDTO;assessment?:AssessmentTopology}){
 const events=useMemo(()=>model.events.map(playbackEvent),[model.events]);
 const [cursor,setCursor]=useState(-1),[playing,setPlaying]=useState(false),[speed,setSpeed]=useState(1);
 const current=events[cursor];
 const inventory=assessment?.topology.nodes as {id:string;name:string;type:string}[]|undefined;
 const names=useMemo(()=>new Map(inventory?.map(n=>[n.id,n.name])??data.nodes.map(n=>[n.id,n.label])),[inventory,data.nodes]);
 const name=(id:unknown)=>names.get(String(id))??String(id??"Not recorded");
 const crowns=assessment?.topology.crown_jewels as string[]|undefined;
 const crownNames=crowns?.map(name).join(", ")||"Not recorded";
 const replayState=useMemo(()=>episodeState(model.events,cursor),[model.events,cursor]);
 const goalReached=replayState.reached.size>0;
 const milestones=useMemo(()=>{
  const seen=new Set<string>();
  return events.flatMap((row,i)=>{
   const label=milestoneLabel(row);
   if(!label)return [];
   const significant=!seen.has(label)||row.goal_reached===true||row.detection===true||(/exploit|pivot|credential/.test(String(row.action_kind))&&row.success===true&&row.state_changed===true);
   seen.add(label);return significant?[i]:[];
  });
 },[events]);
 useEffect(()=>{setCursor(-1);setPlaying(false);},[model.events]);
 useEffect(()=>{if(!playing)return;if(cursor>=events.length-1){setPlaying(false);return;}
 const timer=setTimeout(()=>setCursor(i=>i+1),800/speed);return()=>clearTimeout(timer);
 },[playing,cursor,speed,events.length]);
 const go=(n:number)=>{setPlaying(false);setCursor(n);};
 return <section aria-label="Recorded episode replay">
 <h3>Episode Simulation</h3>
 <p>{model.registered?"Registered Research · MaskablePPO · Frozen evidence · Read-only reconstruction":"Engineering V2 Reasoner / masked heuristic · engineering_simulation · Registered: No"}</p>
 {model.registered&&<p>Chronological PPO validation trajectory — not necessarily literal network connectivity.</p>}
 <p>Replay uses stored episode evidence. It does not rerun the simulation.</p>
 <div className="replay-crown"><span aria-hidden="true">★</span> {crownNames} <Badge>{goalReached?"OBJECTIVE REACHED":"NOT REACHED"}</Badge></div>
 <div className="graph-controls"><button onClick={()=>go(0)} disabled={!events.length}>First</button><button onClick={()=>go(Math.max(-1,cursor-1))}>Previous step</button>
 <button onClick={()=>setPlaying(!playing)} disabled={!events.length||cursor===events.length-1}>{playing?"Pause":"Play"}</button>
 <button onClick={()=>go(Math.min(events.length-1,cursor+1))}>Next step</button><button onClick={()=>go(events.length-1)}>Last</button><button onClick={()=>go(-1)}>Reset</button>
 <button onClick={()=>{setCursor(-1);setPlaying(true);}}>Replay</button>
 <label>Playback speed<select value={speed} onChange={e=>setSpeed(Number(e.target.value))}>{[.5,1,2,4].map(n=><option key={n} value={n}>{n}×</option>)}</select></label></div>
 <label>Episode timeline<input type="range" min={-1} max={Math.max(-1,events.length-1)} value={cursor} onChange={e=>go(Number(e.target.value))}/></label>
 <p className="replay-position">First: {String(events[0]?.step??"Not recorded")} · Current: {String(current?.step??"Entry")} · Last: {String(events.at(-1)?.step??"Not recorded")}</p>
 <p role="status">{current?`Step ${String(current.step)} · ${String(current.action_kind)} · ${String(current.target)}`:"Configured starting context"}</p>
 <details><summary>Recorded milestones ({milestones.length})</summary>{milestones.map(i=><button key={i} onClick={()=>go(i)}>Step {String(events[i].step)} · {milestoneLabel(events[i])}</button>)}</details>

 {current&&<article className="notice replay-current" aria-label="Current step summary">
 <h4>{goalReached?"Objective reached":cursor===events.length-1?"Objective not reached":`Step ${String(current.step)} — ${plain(current.action_kind)} · ${name(current.target)}`}</h4>
 <div className="replay-badges">{milestoneLabel(current)&&<Badge>{milestoneLabel(current)}</Badge>}<Badge>{outcome(current.success)}</Badge>
 {current.state_changed===true&&<Badge>State changed</Badge>}{current.detection===true&&<Badge>Detection recorded</Badge>}</div>
 <Fields value={{step:current.step,action:plain(current.action_kind),target:name(current.target),result:outcome(current.success),state_change:yesNo(current.state_changed),detection:current.detection==="Not recorded"?"Not recorded":current.detection===false?"No detection recorded":current.detection===true?"Detected":"Recorded detection event",reward:current.reward??"Not recorded",objective:goalReached?"Reached":"Not reached"}}/>
 <Mappings value={current.mitre_mappings??current.framework_mappings}/><details><summary>Episode identity and evidence</summary><Fields value={model.identity}/><Fields value={current}/></details></article>}
 <IconGraph data={data} assessment={assessment} mode={assessment?"Combined":"Evidence"} replayState={replayState} activeTarget={current?String(current.target):undefined} activeSource={current?.source!=="Not recorded"?String(current?.source??""):undefined}/>

 {cursor===events.length-1&&events.length>0&&<article className="notice replay-complete" aria-label="Episode complete"><h4>Episode complete</h4>
 <Fields value={{recorded_actions:events.length,successful_actions:events.filter(r=>r.success===true).length,failed_actions:events.filter(r=>r.success===false).length,observed_hosts:data.nodes.filter(n=>n.type==="host"&&replayState.known.has(n.id)).length,recorded_findings:assessment?.recordedFindings??"Not available in episode data",objective:goalReached?"OBJECTIVE REACHED":"NOT REACHED",final_recorded_event:plain(events.at(-1)?.action_kind),crown_jewel:crownNames}}/></article>}
 <p>Muted systems exist in the configured scenario but were not observed at this replay step.</p>
 <div className="table-wrap" style={{maxHeight:320,overflow:"auto"}}><table><thead><tr>{["Step","Event","Target","Result","Detection"].map(h=><th key={h}>{h}</th>)}</tr></thead><tbody>
 {events.map((r,i)=><tr key={i} aria-current={i===cursor?"step":undefined}><td><button onClick={()=>go(i)}>Step {String(r.step)}</button></td><td>{plain(r.action_kind)}</td><td title={String(r.target)}>{name(r.target)}</td><td>{outcome(r.success)}</td><td>{r.detection==="Not recorded"?"Not recorded":r.detection===true?"Detected":r.detection===false?"No detection recorded":"Recorded event"}</td></tr>)}</tbody></table></div>
 </section>;
}
