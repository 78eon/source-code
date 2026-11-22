// @vitest-environment jsdom
import {afterEach,expect,it} from "vitest";
import {cleanup,render,screen} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {ProgressivePath} from "./ProgressivePath";
afterEach(cleanup);
it("reveals recorded branches only after their action and hides failed attempts",async()=>{
 const events=[{step:0,action_kind:"discover_network",success:true,state_changed:true,knowledge_delta:{discovered_nodes:["generated-a","generated-b"]}},
 {step:1,action_kind:"pivot",target:"failed-target",success:false,state_changed:false}];
 render(<ProgressivePath events={events} entry="configured-entry"/>);
 expect(screen.getByText("configured-entry")).toBeTruthy();
 expect(screen.queryByText("generated-a")).toBeNull();
 await userEvent.click(screen.getByRole("button",{name:"Next step"}));
 expect(screen.getByRole("button",{name:"generated-a"})).toBeTruthy();
 expect(screen.getByRole("button",{name:"generated-b"})).toBeTruthy();
 await userEvent.click(screen.getByRole("button",{name:"Next step"}));
 expect(screen.queryByRole("button",{name:/Step 1/})).toBeNull();
 await userEvent.click(screen.getByLabelText("Show failed/non-progressing actions"));
 expect(screen.getByRole("button",{name:/Step 1/})).toBeTruthy();
});
