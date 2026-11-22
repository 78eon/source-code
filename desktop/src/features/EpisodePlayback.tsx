import {useEffect,useMemo,useState} from "react";
import type {Fact,GraphDTO} from "../types";
import {Fields,Mappings} from "../components/EvidenceDisplay";
import {episodeState} from "./episodeState";
import {IconGraph} from "./topology/IconGraph";
import type {AssessmentTopology} from "./topology/EnterpriseStructure";

export interface EpisodePlaybackModel {identity:Fact;events:readonly Fact[];registered:boolean}
export function playbackEvent(row:Fact,index:number):Fact{
 const source=row.source_node;
 return {...row,order:index,source:typeof source==="string"&&source!=="UNKNOWN"?source:"Not recorded",
 target:row.target_entity??row.target??"Not recorded",detection:row.detection_event??row.detected??"Not recorded"};
}
export function EpisodePlayback({model,data,assessment}:{model:EpisodePlaybackModel;data:GraphDTO;assessment?:AssessmentTopology}){
 const events=useMemo(()=>model.events.map(playbackEvent),[model.events]);
 const [cursor,setCursor]=useState(-1),[playing,setPlaying]=useState(false),[speed,setSpeed]=useState(1);
 const current=events[cursor];
 const replayState=useMemo(()=>episodeState(model.events,cursor),[model.events,cursor]);
 const goalReached=replayState.reached.size>0;
 const milestones=useMemo(()=>events.flatMap((row,i)=>row.goal_reached===true||row.state_changed===true||row.detection===true||row.detection_event!=null?[i]:[]),[events]);
 useEffect(()=>{setCursor(-1);setPlaying(false);},[model.events]);
 useEffect(()=>{if(!playing)return;if(cursor>=events.length-1){setPlaying(false);return;}
 const timer=setTimeout(()=>setCursor(i=>i+1),800/speed);return()=>clearTimeout(timer);
 },[playing,cursor,speed,events.length]);
 const go=(n:number)=>{setPlaying(false);setCursor(n);};
 return <section aria-label="Recorded episode replay">
 <h3>Episode Simulation</h3>
 <p>{model.registered?"Registered Research · MaskablePPO · Frozen evidence · Read-only reconstruction":"Engineering V2 Reasoner / masked heuristic · engineering_simulation · Registered: No"}</p>
 {model.registered&&<p>Chronological PPO validation trajectory — not necessarily literal network connectivity.</p>}
 <div className="graph-controls"><button onClick={()=>go(0)} disabled={!events.length}>First</button><button onClick={()=>go(Math.max(-1,cursor-1))}>Previous step</button>
 <button onClick={()=>setPlaying(!playing)} disabled={!events.length||cursor===events.length-1}>{playing?"Pause":"Play"}</button>
 <button onClick={()=>go(Math.min(events.length-1,cursor+1))}>Next step</button><button onClick={()=>go(events.length-1)}>Last</button><button onClick={()=>go(-1)}>Reset</button>
 <button onClick={()=>{setCursor(-1);setPlaying(true);}}>Replay</button>
 <label>Playback speed<select value={speed} onChange={e=>setSpeed(Number(e.target.value))}>{[.5,1,2,4].map(n=><option key={n} value={n}>{n}×</option>)}</select></label></div>
 <label>Episode timeline<input type="range" min={-1} max={Math.max(-1,events.length-1)} value={cursor} onChange={e=>go(Number(e.target.value))}/></label>
 <p role="status">{current?`Step ${String(current.step)} · ${String(current.action_kind)} · ${String(current.target)}`:"Configured starting context"}</p>
 <details><summary>Recorded milestones</summary>{milestones.map(i=><button key={i} onClick={()=>go(i)}>Step {String(events[i].step)} · {String(events[i].action_kind)}</button>)}</details>
 <IconGraph data={data} assessment={assessment} mode={assessment?"Combined":"Evidence"} replayState={replayState} activeTarget={current?String(current.target):undefined} activeSource={current?.source!=="Not recorded"?String(current?.source??""):undefined}/>

 {current&&<article className="notice"><h4>{goalReached?"Objective reached":cursor===events.length-1?"Objective not reached":"Recorded action"}</h4>
 <p>Source: {String(current.source)} → Action: {String(current.simulator_action??current.action_kind)} → Target: {String(current.target)}</p>
 <p>Action marker shows the recorded association. Source-to-target routing requires separate structural evidence.</p>
 <Fields value={{step:current.step,success:current.success??"Not recorded",state_changed:current.state_changed??"Not recorded",reward:current.reward??"Not recorded",detection:current.detection,goal:current.goal_reached??"Not recorded"}}/>
 {current.detection!==false&&current.detection!=="Not recorded"&&<p>🛡 Recorded detection: {String(current.detection)}</p>}
 <Mappings value={current.mitre_mappings??current.framework_mappings}/><details><summary>Episode identity and evidence</summary><Fields value={model.identity}/><Fields value={current}/></details></article>}
 <div className="table-wrap" style={{maxHeight:320,overflow:"auto"}}><table><thead><tr>{["Step","Action","Target","Result","State change","Detection","Reward","Goal"].map(h=><th key={h}>{h}</th>)}</tr></thead><tbody>
 {events.map((r,i)=><tr key={i} aria-current={i===cursor?"step":undefined}><td><button onClick={()=>go(i)}>Step {String(r.step)}</button></td>{[r.action_kind,r.target,r.success,r.state_changed,r.detection,r.reward,r.goal_reached].map((v,j)=><td key={j}>{String(v??"Not recorded")}</td>)}</tr>)}</tbody></table></div>
 </section>;
}
