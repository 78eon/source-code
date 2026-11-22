import { expect, test } from "@playwright/test";
import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

// Run only in the explicit network-disabled engineering runner, with an ephemeral API/state.
test("real synthetic wizard, execution, graph, explanations and downloaded reports",async({page})=>{
 test.skip(process.env.SECURITY_RL_ENGINEERING_E2E!=="1","requires the isolated engineering API runner");
 const output=process.env.SECURITY_RL_ENGINEERING_E2E_OUTPUT??"/tmp/engineering-e2e";
 mkdirSync(output,{recursive:true});
 const errors:string[]=[];const writes:string[]=[];
 page.on("pageerror",error=>errors.push(error.message));
 page.on("request",request=>{if(request.method()==="POST")writes.push(new URL(request.url()).pathname);});
 await page.goto("/");
 await page.getByLabel("Local API token").fill(process.env.SECURITY_RL_API_TOKEN!);
 await page.getByRole("button",{name:"Connect",exact:true}).click();
 await page.getByRole("button",{name:"Example Scenarios",exact:true}).click();
 await expect(page.getByRole("region",{name:"Example scenarios"})).toBeVisible();
 await expect(page.getByRole("button",{name:"Use this scenario",exact:true})).toHaveCount(8);
 await page.screenshot({path:join(output,"00-example-scenarios.png"),fullPage:true});
 await page.locator("article").filter({has:page.getByRole("heading",{name:"Small Office",exact:true})})
  .getByRole("button",{name:"Use this scenario",exact:true}).click();
 await expect(page.getByRole("region",{name:"New simulation wizard"})).toBeVisible();
 await expect(page.getByLabel("Load example scenario")).toHaveValue("small-office");
 await expect(page.getByText("PPO: Not bound to this generated topology",{exact:true})).toBeVisible();
 await expect(page.getByText("SIMULATED SECURITY ASSESSMENT — NOT A LIVE PENETRATION TEST",{exact:true})).toBeVisible();
 await page.getByLabel("Simulation name",{exact:true}).fill("Synthetic enterprise dissertation demonstration");
 await page.screenshot({path:join(output,"01-new-simulation.png"),fullPage:true});
 await page.setViewportSize({width:1440,height:900});
 async function captureStep(index:number){
   const wizard=page.getByRole("region",{name:"New simulation wizard"});
   for(const width of [1440,820]){
     await page.setViewportSize({width,height:900});
     const errors=await wizard.evaluate(el=>{
       const issues:string[]=[];
       if(el.scrollWidth>el.clientWidth+2)issues.push("Wizard overflows");
       for(const box of el.querySelectorAll<HTMLInputElement>('label > input[type=checkbox]')){
         const label=box.parentElement!, rect=box.getBoundingClientRect();
         const text=[...label.childNodes].find(n=>n.nodeType===Node.TEXT_NODE&&n.textContent?.trim());
         if(!text)continue;
         const range=document.createRange();range.selectNodeContents(text);
         const words=range.getBoundingClientRect();
         if(rect.width>32||words.width<Math.min(34,text.textContent!.trim().length*4)||words.left-rect.right>18||Math.abs(words.y-rect.y)>20||label.offsetHeight>70)issues.push(label.textContent??"checkbox");
       }
       return issues;
     });
     expect(errors).toEqual([]);
   }
   await page.setViewportSize({width:1440,height:900});
   await wizard.screenshot({path:join(output,"wizard-"+String(index+1).padStart(2,"0")+".png")});
 }
 for(let i=0;i<9;i++){await captureStep(i);if(i<8)await page.getByRole("button",{name:"Next",exact:true}).click();}

 await page.getByRole("button",{name:"Review Simulation",exact:true}).click();
 await expect(page.getByRole("button",{name:"Create Simulation",exact:true})).toBeVisible();
 await captureStep(9);
 expect(writes).toEqual(["/api/engineering-simulations/preview"]);
 await page.screenshot({path:join(output,"02-review.png"),fullPage:true});
 await page.getByRole("button",{name:"Create Simulation",exact:true}).click();
 await expect(page.getByRole("button",{name:"Run Simulation",exact:true})).toBeVisible();
 await page.getByRole("button",{name:"Run Simulation",exact:true}).click();
 await expect(page.getByRole("button",{name:"Recorded run complete",exact:true})).toBeVisible({timeout:60000});
 await expect(page.getByText("Recorded playback after execution — these are actual stored simulator events.")).toBeVisible();
 await page.screenshot({path:join(output,"03-recorded-run.png"),fullPage:true});
 await page.getByRole("button",{name:"Next step",exact:true}).click();
 await page.getByRole("button",{name:"Attack / Provenance Graph",exact:true}).click();
 await expect(page.getByText("Enterprise Topology Structure",{exact:true})).toBeVisible();
 await page.getByLabel("Graph mode").selectOption("Topology");
 await expect(page.getByText("Topology Profile",{exact:true})).toBeVisible();
 await page.getByLabel("Graph mode").selectOption("Evidence");
 await expect(page.locator("canvas").first()).toBeVisible();
 await expect(page.getByText("Stored engineering simulation graph",{exact:false})).toBeVisible();
 await page.screenshot({path:join(output,"04-canonical-graph.png"),fullPage:true});
 await page.getByLabel("Recorded graph filter").selectOption("evidence");
 await expect(page.locator("canvas").first()).toBeVisible();
 await page.getByRole("button",{name:"Explainable Decisions",exact:true}).click();
 await expect(page.getByText("Selected playback event explanation")).toBeVisible();
 await expect(page.locator("pre").filter({hasText:"selection_rule"}).last()).toBeVisible();
 await page.getByRole("button",{name:"Assessment Report",exact:true}).click();
 await expect(page.getByRole("region",{name:"Stored simulation assessment"})).toBeVisible();
 await expect(page.getByText("Executive summary",{exact:true})).toBeVisible();
 await page.screenshot({path:join(output,"05-assessment-report.png"),fullPage:true});
 for(const [label,extension] of [["Download HTML","html"],["Download PDF","pdf"],["Export JSON","json"]]){
  const waiting=page.waitForEvent("download");
  await page.getByRole("button",{name:label,exact:true}).click();
  const download=await waiting;const target=join(output,"assessment."+extension);
  await download.saveAs(target);const data=readFileSync(target);
  expect(data.length).toBeGreaterThan(1000);
  if(extension==="pdf")expect(data.subarray(0,8).toString()).toBe("%PDF-1.4");
  if(extension==="html")expect(data.toString()).toContain("SIMULATED SECURITY ASSESSMENT");
  if(extension==="json"){
   const report=JSON.parse(data.toString());expect(report.evidence_class).toBe("engineering_simulation");
   expect(report.research_status).toBe("not_registered");expect(report.provenance.report_id).toHaveLength(64);
   expect(report.decision_engine).toBe("Engineering V2 Reasoner / masked heuristic");
   expect(report.provenance.example_provenance.preset_id).toBe("small-office");
   expect(report.provenance.example_provenance.modified).toBe(true);
  }
 }
 // Reload the client and reopen persisted evidence; never execute the run again.
 await page.reload();
 await page.getByLabel("Local API token").fill(process.env.SECURITY_RL_API_TOKEN!);
 await page.getByRole("button",{name:"Connect",exact:true}).click();
 await page.getByRole("button",{name:"Saved Simulations",exact:true}).first().click();
 await page.getByRole("button",{name:"Open assessment",exact:true}).click();
 await expect(page.getByRole("button",{name:"Recorded run complete",exact:true})).toBeVisible();
 expect(writes.filter(path=>path.endsWith("/run"))).toHaveLength(1);
 expect(writes.every(path=>path.startsWith("/api/engineering-simulations"))).toBe(true);
 expect(errors).toEqual([]);
});

test("bounded service templates survive review and storage",async({page})=>{
 test.skip(process.env.SECURITY_RL_ENGINEERING_E2E!=="1","requires isolated engineering runner");
 await page.goto("/");
 await page.getByLabel("Local API token").fill(process.env.SECURITY_RL_API_TOKEN!);
 await page.getByRole("button",{name:"Connect",exact:true}).click();
 await page.getByRole("button",{name:"New Simulation",exact:true}).first().click();
 for(let i=0;i<3;i++)await page.getByRole("button",{name:"Next",exact:true}).click();
 for(let n=2;n<=12;n++){
  await page.getByRole("button",{name:"Add service template",exact:true}).click();
  await expect(page.getByText(`Services configured: ${n} / 12`,{exact:true})).toBeVisible();
  if(n===8)await expect(page.getByRole("combobox",{name:"Service 8 name",exact:true})).toBeVisible();
 }
 await expect(page.getByRole("button",{name:"Add service template",exact:true})).toBeDisabled();
 await expect(page.getByText("Maximum 12 service templates for one bounded engineering simulation.",{exact:true})).toBeVisible();
 for(let i=0;i<5;i++)await page.getByRole("button",{name:"Next",exact:true}).click();
 await page.getByRole("button",{name:"Review Simulation",exact:true}).click();
 await page.getByRole("button",{name:"Create Simulation",exact:true}).click();
 await expect(page.getByRole("button",{name:"Run Simulation",exact:true})).toBeVisible();
});
