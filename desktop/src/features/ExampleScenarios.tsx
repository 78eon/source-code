import type { ExampleScenario } from "./simulationTypes";
export function ExampleScenarios({items,onUse}:{items:ExampleScenario[];onUse:(example:ExampleScenario)=>void}) {
 return <section aria-label="Example scenarios"><h2>Synthetic example environments</h2>
  <p>Versioned engineering templates, not empirical assessments. Use a scenario to open an editable wizard;
   nothing is saved or executed until you explicitly create and run it. Outcomes are not guaranteed.</p>
  <div className="simulation-library">{items.map(item=><article className="wizard-card" key={item.preset_id}>
   <p className="eyebrow">ENGINEERING_SIMULATION · NOT_REGISTERED · V{item.version}</p>
   <h3>{item.label}</h3><p>{item.purpose}</p>
   <dl><dt>Devices / subnets</dt><dd>{item.hosts} / {item.subnets}</dd><dt>Risk / segmentation</dt>
    <dd>{item.risk_profile} / {item.segmentation}</dd><dt>Critical asset</dt><dd>{item.critical_asset}</dd>
    <dt>Difficulty</dt><dd>{item.difficulty}</dd><dt>Default seed</dt><dd>{item.default_seed}</dd></dl>
   <details><summary>Template identities</summary><p>{item.preset_id} · version {item.version}</p>
    <p className="hash">Specification: {item.specification_sha256}</p><p className="hash">Topology: {item.topology_sha256}</p></details>
   <button onClick={()=>onUse(item)}>Use this scenario</button>
  </article>)}</div>
 </section>;
}
