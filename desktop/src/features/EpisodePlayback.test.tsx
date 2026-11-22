// @vitest-environment jsdom
import {render,screen,fireEvent,cleanup} from "@testing-library/react";
import {afterEach,it,expect,vi} from "vitest";
import {EpisodePlayback,playbackEvent} from "./EpisodePlayback";
vi.mock("./topology/IconGraph",()=>({IconGraph:({activeTarget}:{activeTarget:string})=><p>Highlighted {activeTarget}</p>}));
afterEach(cleanup);
it("selects recorded steps and keeps detection independent of success",()=>{
 const events=[{step:0,action_kind:"discover",target:"first",success:true,detected:false},{step:1,action_kind:"access",target:"objective",reward:100,goal_reached:true}];
 render(<EpisodePlayback model={{events,identity:{episode:"test"},registered:true}} data={{source:"neo4j",graph_id:null,nodes:[],edges:[]}}/>);
 fireEvent.click(screen.getByRole("button",{name:"Next step"}));
 expect(screen.getByText("Highlighted first")).toBeTruthy();
 expect(playbackEvent(events[0],0).source).toBe("Not recorded");
 expect(playbackEvent(events[0],0).detection).toBe(false);
 fireEvent.click(screen.getByRole("button",{name:"Last"}));
 expect(screen.getByRole("heading",{name:"Objective reached"})).toBeTruthy();
 fireEvent.change(screen.getByLabelText("Playback speed"),{target:{value:"4"}});
 fireEvent.click(screen.getByRole("button",{name:"Reset"}));
 expect(screen.getByText("Configured starting context")).toBeTruthy();
});

it("synchronizes play speed, pause, timeline and event selection",()=>{
 vi.useFakeTimers();
 try{
  const events=[0,1,2].map(step=>({step,action_kind:"enumerate",target:"node-"+step,success:step!==1,state_changed:step===0}));
  render(<EpisodePlayback model={{events,identity:{simulation_id:"selected",episode_id:"episode"},registered:false}} data={{source:"neo4j",graph_id:"graph",nodes:[],edges:[]}}/>);
  fireEvent.change(screen.getByLabelText("Playback speed"),{target:{value:"4"}});
  fireEvent.click(screen.getByRole("button",{name:"Play"}));
  // Fire timer through React's event flush.
  fireEvent.click(screen.getByRole("button",{name:"Pause"}));
  fireEvent.click(screen.getByRole("button",{name:"First"}));
  expect(screen.getByText("Highlighted node-0")).toBeTruthy();
  fireEvent.click(screen.getByRole("button",{name:"Next step"}));
  expect(screen.getByText("Highlighted node-1")).toBeTruthy();
  fireEvent.click(screen.getByRole("button",{name:"Previous step"}));
  expect(screen.getByText("Highlighted node-0")).toBeTruthy();
  fireEvent.change(screen.getByLabelText("Episode timeline"),{target:{value:"2"}});
  expect(screen.getByRole("heading",{name:"Objective not reached"})).toBeTruthy();
  fireEvent.click(screen.getByRole("button",{name:"Step 1"}));
  expect(screen.getByLabelText("Episode timeline")).toHaveProperty("value","1");
  fireEvent.click(screen.getByRole("button",{name:"Replay"}));
  expect(screen.getByText("Configured starting context")).toBeTruthy();
 }finally{vi.useRealTimers();}
});
