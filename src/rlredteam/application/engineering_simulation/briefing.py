"""Stakeholder interpretation of stored engineering assessments."""
from collections import Counter, defaultdict
from .topology_brief import describe
from ..graph_presentation import build_presentation
from ..progression_figures import add_figures
from ..assessment_layout import Document
from ..assessment_context import UNKNOWN, context, framework, outcome

LEVELS = ("Critical","High","Medium","Low","Informational")


def document(d):
    scope,summary=d["scope"],d["summary"]
    controls=scope["controls"]
    episodes=d["recorded_episodes"]
    events=[e for ep in episodes for e in ep["events"]]
    devices=scope["devices"]
    critical=scope.get("critical_asset") or "the designated critical asset"
    reached=summary["objective_reached"]
    findings=d["findings"]
    groups=defaultdict(list)
    for f in findings:
        groups[f["severity"]].append(f)
    status="Reached" if reached else "Unreached"
    result=("The simulation reached the designated critical asset." if reached else
            "The recorded simulation did not reach the designated critical asset. This does not establish that the environment is secure.")
    doc=Document("Engineering Simulation Assessment",d["disclaimer"],d["name"],
                 f"{d['generated_at']}  |  engineering_simulation  |  not_registered")
    doc.graph_presentation=build_presentation(scope.get("configured_topology", {}) | {"crown_jewels":scope.get("objective_assets",[])})
    s=doc.section("Purpose and executive summary")
    s.heading("Purpose of the Assessment")
    s.prose(f"This assessment examined {d['name']}, a bounded enterprise model of {summary['systems']} systems across {len(scope['subnets'])} configured segments. The objective was to {scope['objective']}. The designated asset was {critical}.",
            f"The {d['decision_engine']} selected simulated actions using observable information. Across {len(episodes)} recorded episodes, the environment returned {len(events)} action outcomes. {result}",
            f"The assessment identified {len(findings)} observed synthetic assignments. The highest observed severity was {summary['highest_observed_severity']}. Findings refer to assessed assignments; unobserved configuration is outside this count.",
            "Read the control settings alongside the recorded stopping points. A setting may change model behaviour, but isolating its effect requires a matched comparison. Prioritise the highest observed themes, then compare a separately recorded scenario after changing one control.")
    context(s,"Configured inventory and controls, selected actions, outcome flags and objective result.",
            "Severity bands, grouped finding themes and chronological summaries.",
            "ATT&CK labels, catalogue annotations and suggested control improvements.",
            "Production applicability, calibrated risk, actual business impact and the causal effect of a control.")
    s=doc.section("Assessment at a glance")
    counts=Counter()
    for group in devices: counts[group["category"]]+=group["count"]
    s.table(("Scope","Included"),[("Systems",summary["systems"]),("Configured segments",len(scope["subnets"])),
        ("Configured public-facing systems",sum(g["count"] for g in devices if g.get("internet_exposed"))),
        ("Designated critical assets",len(scope["objective_assets"]) if "objective_assets" in scope else UNKNOWN),
        ("Segmentation profile",scope.get("segmentation_profile") or UNKNOWN),
        *[(key.replace("_"," ").title(),num) for key,num in counts.items()],
        ("Objective",status),("Observed findings",len(findings)),("Decision Engine",d["decision_engine"])])
    s.table(("Control","Configured state"),[(k.replace("_"," ").capitalize(), ("Enabled" if v else "Disabled") if isinstance(v,bool) else v) for k,v in controls.items()])
    s.prose("Observed severity counts: "+", ".join(f"{level} {len(groups[level])}" for level in LEVELS)+".")
    s.prose("Assessment phases: configure the scenario, discover assets, assess services, select actions, record evidence and interpret security implications.")
    s=doc.section("Enterprise Network Topology")
    describe(s,d)
    s.heading("Modelled strengths / controls present")
    on=[k.replace("_"," ") for k,v in controls.items() if v is True]
    off=[k.replace("_"," ") for k,v in controls.items() if v is False]
    s.prose("Enabled controls: "+(", ".join(on) or "none recorded")+".",
            "Disabled controls: "+(", ".join(off) or "none recorded")+".",
            f"Configured patch coverage: {controls.get('patch_coverage',UNKNOWN)}. Critical asset: {critical}.")
    s.heading("Controls that helped: evidence boundary")
    s.prose(f"The recorded objective status was {status.lower()} with these controls configured. Their individual contributions were not measured. Monitoring configuration alone does not establish a detection.")
    s=doc.section("Observed Attack / Provenance Graph")
    s.prose("Evidence-derived view of the recorded simulation progression. Relationships shown as literal connectivity only where supported by recorded evidence.",
            "Circular icons identify entities and events. Dark green marks successful actions, light green marks discovery, and grey marks recorded relationships. Dashed links connect milestones in time. Targets without a source are attached to their recorded action.")
    names={n["id"]: n.get("name") for n in scope.get("configured_topology",{}).get("nodes",scope.get("generated_inventory", []))}
    for i, ep in enumerate(episodes, 1):
        s.heading(f"Episode {i}")
        add_figures(s, ep["events"], names, critical, ep["goal_reached"])
    s=doc.section("How the assessment progressed")
    s.heading("DECISION ENGINE")
    s.prose(f"{d['decision_engine']} ranked candidates using observed knowledge and the model’s action mask. Its scores describe heuristic preference. No PPO checkpoint controlled this run.")
    outcomes=[]
    for i,ep in enumerate(episodes,1):
        rows=ep["events"]
        if not rows:
            s.prose(f"Episode {i} contains no recorded actions.");continue
        first,last=rows[0],rows[-1]
        s.heading(f"Episode {i} | {ep['outcome']}")
        s.prose(f"The first recorded action was {first['action_kind'].replace('_',' ')} on {first['target']}. Of {len(rows)} actions, {sum(r['success'] is False for r in rows)} returned a failed outcome.")
        # First occurrences preserve recorded order without suggesting a connected route.
        kinds={}
        for row in rows:kinds.setdefault(row["action_kind"],row)
        s.figure(f"Figure 2.{i}. First occurrence of each action category in time order",
                 [f"Step {r['step']} | {k.replace('_',' ')} | {r['target']}" for k,r in kinds.items()])
        add_figures(s, rows, names, critical, ep["goal_reached"], detail=True)
        s.prose(f"The record ends at step {last['step']} with {last['simulator_action']} ({outcome(last['success']).lower()}).")
        if not ep["goal_reached"]:s.prose("The recorded evidence does not establish a single causal reason for the stopping point.")
        outcomes.append((f"Episode {i}",last["simulator_action"],ep["outcome"]))
    s=doc.section("Findings report card")
    s.prose("Severity is model-derived. Each finding requires a successful simulator assessment. CVSS catalogue values, when present, are contextual annotations.")
    s.table(("Severity","Recorded findings","Priority action"),[(level,len(groups[level]),"Review affected service configuration" if groups[level] else "No observed finding in this band") for level in LEVELS])
    themes=defaultdict(list)
    for f in findings:
        themes[(f["service"],f["severity"])].append(f)
    if themes:
        s.table(("Finding theme","Severity","Affected area","Priority action"),[
            (f"{service} service exposure", level, f"{len(set(f['host'] for f in items))} modelled hosts",
             "Review patch and hardening settings") for (service,level),items in
             sorted(themes.items(),key=lambda item:(LEVELS.index(item[0][1]),item[0][0]))])
    for level in LEVELS:
        items=groups[level]
        if not items:continue
        areas=Counter(f["service"] for f in items)
        s.heading(f"{level} | Assessed service weaknesses")
        s.prose(f"Recorded: {len(items)} assignments across {len({f['host'] for f in items})} hosts. Affected services: "+", ".join(f"{name} ({n})" for name,n in areas.items())+".",
                f"Derived: the {level.lower()} band groups assignments with similar model scores. A successful assessment reveals a condition; it need not result in access.",
                "Contextual: review service exposure, patching and hardening for this group. Unknown: exploitability and impact on a production deployment.",
                f"Example finding: {items[0]['finding_id']} on {items[0]['host']}. Its affected service is {items[0]['service']}. "
                f"Evidence reference: {next(iter(items[0]['evidence_ids']),UNKNOWN)}.",
                "Priority: "+("Immediate" if level in {"Critical","High"} else "Short term")+
                ". Review the affected service group, apply one modelled control change, and compare both finding count and objective outcome.",
                "ATT&CK context: "+(", ".join(dict.fromkeys(m["technique_id"] for f in items for m in f["mitre"] if m.get("technique_id"))) or "No mapping retained")+".")
    if not findings:s.prose("No assignment met the observed-finding rule. This leaves unassessed services unresolved.")
    s=doc.section("ATT&CK context and remediation")
    framework(s,[(e["action_kind"].replace("_"," "),f"Step {e['step']} · {e['target']}",e.get("mitre_mappings")) for e in events])
    s.heading("Prioritised remediation roadmap")
    s.table(("Priority","Action","Reason / evidence"),[
        ("Immediate","Triage high-severity service groups" if groups["Critical"] or groups["High"] else "Review the recorded stopping point",f"{len(groups['Critical'])+len(groups['High'])} high or critical model findings."),
        ("Short term","Review target access and segment restrictions",f"Objective: {critical}; outcome: {status}."),
        ("Medium term","Compare one control change at a time","Baseline settings and episode outcomes are recorded."),
        ("Strategic","Validate relevant assumptions with asset owners","Model observations alone cannot establish real impact.")])
    s=doc.section("Final outcome and next steps")
    s.table(("Stage","Final recorded event","Outcome"),outcomes)
    s.prose(f"The simulation identified {len(findings)} synthetic findings. {result}")
    s.figure("Figure 3. Assessment in six decisions",[f"Start: {summary['systems']} modelled systems",
            f"Observe: {len(findings)} assessed assignments",f"Decide: heuristic selected {len(events)} actions",
            f"Outcome: objective {status.lower()}","Learn: individual control effects remain open","Next: change one control and compare the recorded outcomes"])
    s=doc.section("Recorded Assessment Progression — Final State")
    for i,ep in enumerate(episodes,1):
        s.heading(f"Episode {i}")
        add_figures(s,ep["events"],names,critical,ep["goal_reached"])
    s=doc.section("Evidence appendix")
    s.heading("Generated host inventory")
    s.table(("Asset","Role","Subnet index"),[(n["id"],n["attributes"].get("role",UNKNOWN),n["attributes"].get("subnet",UNKNOWN)) for n in scope["generated_inventory"]])
    if findings:s.table(("Finding ID","Host / service","Model severity","Example evidence ID"),[(f["finding_id"],f"{f['host']} / {f['service']}",f["severity"],next(iter(f["evidence_ids"]),UNKNOWN)) for f in findings])
    s.prose("Full event rows, evidence references, configuration, graph and mappings are preserved in the companion JSON.")
    s.table(("Provenance","Value"),[(k,d["provenance"][k]) for k in ("report_id","source_sha256","topology_sha256","specification_sha256") if d["provenance"].get(k)])
    return doc
