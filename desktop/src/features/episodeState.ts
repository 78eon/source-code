import type {Fact} from "../types";
export interface ReplayState {known:Set<string>;access:Map<string,string>;evidence:Set<string>;reached:Set<string>}
export function episodeState(events:readonly Fact[],cursor:number):ReplayState{
 const state:ReplayState={known:new Set(),access:new Map(),evidence:new Set(),reached:new Set()};
 const add=(id:unknown)=>{if(typeof id==="string"&&id&&id!=="UNKNOWN")state.known.add(id);};
 for(const row of events.slice(0,cursor+1)){
  add(row.target??row.target_entity);add(row.source_node);
  if(typeof row.evidence_id==="string")state.evidence.add(row.evidence_id);
  const delta=row.knowledge_delta as {discovered_nodes?:string[];access_changes?:string[][];observed_edges?:string[][]}|undefined;
  delta?.discovered_nodes?.forEach(add);
  delta?.observed_edges?.forEach(([a,b])=>{add(a);add(b);});
  delta?.access_changes?.forEach(([id,level])=>{add(id);state.access.set(id,level);});
  if(row.goal_reached===true&&typeof (row.target??row.target_entity)==="string")state.reached.add(String(row.target??row.target_entity));
 }
 return state;
}
