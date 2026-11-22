import { expect,test } from "@playwright/test";
import { mkdirSync,readFileSync } from "node:fs";
import { join } from "node:path";

test("frozen PPO validation selection, chronology and read-only report downloads",async({page})=>{
 test.skip(process.env.SECURITY_RL_RESEARCH_TRAJECTORY_E2E!=="1","requires explicit read-only campaign runner");
 const output=process.env.SECURITY_RL_RESEARCH_TRAJECTORY_E2E_OUTPUT??"/tmp/research-trajectory-e2e";
 mkdirSync(output,{recursive:true});const mutations:string[]=[];const errors:string[]=[];
 page.on("request",r=>{if(!['GET','OPTIONS'].includes(r.method()))mutations.push(r.url());});
 page.on("pageerror",e=>errors.push(e.message));
 await page.goto("/");
 await page.getByLabel("Local API token").fill(process.env.SECURITY_RL_API_TOKEN!);
 await page.getByRole("button",{name:"Connect",exact:true}).click();
 await page.getByRole("button",{name:"Registered Research",exact:true}).click();
 await expect(page.getByText("Policy validation summary")).toBeVisible();
 await page.screenshot({path:join(output,"00-validation.png")});
 await page.getByRole("button",{name:"PPO Trajectories",exact:true}).click();
 await expect(page.getByRole("list",{name:"Chronological PPO trajectory"})).toHaveCount(0);
 await page.getByRole("button",{name:"View RL Attack Journey"}).click();
 await expect(page.getByLabel("Training seed / policy").locator("option")).toHaveCount(10);
 await expect(page.getByLabel("Validation topology").locator("option")).toHaveCount(20);
 await expect(page.getByLabel("Training seed / policy")).toHaveValue("42");
 await expect(page.getByLabel("Validation topology")).toHaveValue("1001");
 await expect(page.getByLabel("Evaluation episode seed")).toHaveValue("19001");
 await expect(page.locator('.journey-ranges > li').last()).toBeVisible();
 const summary=page.getByRole("region",{name:"Recorded trajectory summary"});
 await expect(summary).toContainText("184.37");await expect(summary).toContainText("77");
 await expect(page.getByText("Source host",{exact:true}).locator("..")).toContainText("Not recorded");
 await page.screenshot({path:join(output,'01-frozen-episode.png'),fullPage:true});
 await page.getByRole("button",{name:/Terminal objective reached/}).click();
 await page.getByRole("list",{name:"Chronological PPO trajectory"}).getByRole("button").last().click();
 const selected=page.getByRole("complementary",{name:"Selected recorded action"});
 await expect(selected).toContainText("930");await expect(selected).toContainText("access_asset:asset_crown");
 await page.getByLabel("Validation topology").selectOption("1002");
 await expect(summary.locator('dd').filter({hasText:/^1002$/})).toBeVisible();
 await page.getByLabel("Training seed / policy").selectOption("43");
 await expect(summary.locator('dd').filter({hasText:/^43$/})).toBeVisible();
 await page.getByLabel("Training seed / policy").selectOption("42");
 await expect(summary).toContainText("184.37");
 await page.getByRole("button",{name:"Generate Research Trajectory Report",exact:true}).click();
 await expect(page.getByRole("region",{name:"Research trajectory report"})).toBeVisible();
 await page.screenshot({path:join(output,'02-report-downloads.png'),fullPage:true});
 for(const [label,format] of [["Download HTML","html"],["Download PDF","pdf"],["Export JSON","json"]]){
  const waiting=page.waitForEvent('download');await page.getByRole('button',{name:label,exact:true}).click();
  const download=await waiting;const target=join(output,`research-ppo-42-1001-19001.${format}`);
  await download.saveAs(target);const bytes=readFileSync(target);expect(bytes.length).toBeGreaterThan(1000);
  if(format==='pdf')expect(bytes.subarray(0,8).toString()).toBe('%PDF-1.4');
  if(format==='html'){expect(bytes.toString()).toContain('REGISTERED PPO VALIDATION EVIDENCE — READ-ONLY RECONSTRUCTION');expect(bytes.toString()).toContain('Not recorded');}
  if(format==='json'){
   const data=JSON.parse(bytes.toString());expect(data.steps).toHaveLength(77);expect(data.summary.total_return).toBe(184.37);
   expect(data.identity.training_seed).toBe(42);expect(data.identity.topology_seed).toBe(1001);expect(data.identity.evaluation_episode_seed).toBe(19001);
   expect(data.chronology.meaning).toBe('chronological_order_only');expect(data.chronology.links).toHaveLength(76);
   expect(data.evidence_availability['Source host']).toBe('Not recorded');expect(data.evidence_availability['Action masks']).toBe('Not recorded');
   expect(data.steps[76].recorded.goal_reached).toBe(true);
  }
 }
 expect(mutations).toEqual([]);expect(errors).toEqual([]);
});
