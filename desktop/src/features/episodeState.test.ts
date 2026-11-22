import {it,expect} from "vitest";
import {episodeState} from "./episodeState";
it("derives only prefix knowledge and access, with no inferred goal access",()=>{
 const events=[{step:0,target:"host",evidence_id:"e0",success:true,detected:true},
 {step:1,target:"service",knowledge_delta:{discovered_nodes:["other"],access_changes:[["host","user"]]}},
 {step:2,target:"crown",goal_reached:true}];
 expect(episodeState(events,-1).known.size).toBe(0);
 expect(episodeState(events,0).access.size).toBe(0);
 expect(episodeState(events,1).known.has("crown")).toBe(false);
 expect(episodeState(events,1).access.get("host")).toBe("user");
 expect(episodeState(events,2).reached.has("crown")).toBe(true);
});
