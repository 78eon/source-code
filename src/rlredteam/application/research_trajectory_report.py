"""Human-readable account of one frozen validation episode."""
from .progression_figures import add_figures
from . import assessment_layout as layout
from .assessment_context import UNKNOWN, comparison, context, framework, outcome
from .research_trajectories import LABEL


def document(d):
    identity=d["identity"]
    summary=d["summary"]
    rows=[entry["recorded"] for entry in d["steps"]]
    end=rows[-1]
    j=d["journey"]
    groups=j["groups"]
    total=summary["total_steps"]
    result="reached" if summary["objective_reached"] else "did not reach"
    target=end.get("target_entity") or UNKNOWN
    final=f"The frozen MaskablePPO policy completed {total} recorded actions and {result} the designated synthetic objective. The final action targeted {target}."
    doc=layout.Document("Registered PPO Research Assessment",LABEL,
                        f"Policy {identity['training_seed']} / validation topology {identity['topology_seed']}",
                        f"Evaluation episode seed {identity['evaluation_episode_seed']}")
    s=doc.section("Purpose and executive summary")
    s.heading("Purpose of the Assessment")
    s.prose("This report reconstructs a validation episode from the registered enterprise simulator. It asks how a learned policy progressed through a topology unseen during training and which recorded events support the outcome.",
            f"{final} The simulator returned {summary['total_return']} over the episode. The recorded terminal outcome was {summary['terminal_outcome']}.",
            f"The sequence begins with {rows[0].get('simulator_action') or UNKNOWN}. Across the episode, {sum(r.get('success') is False for r in rows)} actions returned a failed outcome. The order shows how the assessment unfolded; adjacent targets alone do not establish a network connection.",
            "Defenders can review the access prerequisites of successful transitions and compare them with intended controls. The episode measures task performance inside the registered distribution. It does not measure control effectiveness or compromise of a real enterprise.")
    context(s,"Frozen policy and topology identities, actions, targets, rewards, simulator flags and source rows.",
            "Analyst lifecycle groups and notable-event labels derived deterministically from recorded outcomes.",
            "ATT&CK mappings and defensive implications of the simulated transitions.",
            "Not recorded: policy logits, alternative probabilities, complete observation and mask vectors, neural reasoning and missing host state. Production applicability and actual business impact are unestablished.")
    s=doc.section("Assessment at a glance")
    s.table(("Area","Recorded evidence"),[("Decision Engine","MaskablePPO"),("Training / validation topology / evaluation seed",f"{identity['training_seed']} / {identity['topology_seed']} / {identity['evaluation_episode_seed']}"),
        ("Actions / episode return",f"{total} / {summary['total_return']}"),("Final action",end.get("simulator_action") or UNKNOWN),
        ("Objective result",summary["terminal_outcome"]),("Final target / reward",f"{target} / {end.get('reward',UNKNOWN)}"),("Scope","One registered validation topology; held-out evaluation excluded"),
        ("Asset, subnet and control counts","Not recorded for this episode; generator limits are distribution bounds.")])
    s.heading("Registered topology context")
    s.prose("Registered PPO trajectory overlay — chronological evidence does not necessarily imply literal network connectivity.")
    s.prose("A topology seed and content hash identify the environment. The available validation records supply target identifiers but no structural snapshot. A tier diagram or host-to-host route would require additional evidence.")
    s.prose("This reconstruction reads validation records. It does not import trajectory records into PostgreSQL or Neo4j.")
    s=doc.section("Autonomous RL Decision Intelligence")
    s.prose("MaskablePPO learned a state-dependent policy across episodes in the registered simulator distribution. Training reward encouraged progress toward the synthetic objective. Action masks constrained which actions the policy could select.",
            "During validation, the policy was frozen. At each decision it selected a simulated action, the environment applied a transition and returned an outcome and reward, and the policy received its next observation. This is the sequential mechanism through which RL contributed to attack-path discovery.",
            "Zero-shot validation here means applying the trained policy to an unseen registered validation topology without further training. The records show the selected action, not why the neural policy preferred it over another.")
    s.figure("Original experiment: sequential decision cycle",["Observable state and valid-action mask","Frozen PPO selection","Simulator outcome and reward","Updated state and next decision"])
    s.table(("Scripted agent","PPO policy"),[("Predetermined rules","Learned decision policy"),("Manual branching","State-dependent action selection"),("No reward-based training","Behaviour learned across rewarded episodes")])
    comparison(s)
    s=doc.section("Observed Attack / Provenance Graph")
    s.prose("Chronological PPO validation trajectory — not necessarily literal network connectivity.")
    add_figures(s, rows, {}, "Designated objective", summary["objective_reached"], ppo=True)
    s=doc.section("How the assessment progressed")
    add_figures(s, rows, {}, "Designated objective", summary["objective_reached"], detail=True, ppo=True)
    s.prose("Read the groups in time order. The project lifecycle describes the type of activity. It does not establish a causal chain or reproduce PPO attention.")
    s.figure("Chronological PPO validation trajectory — not literal network connectivity",
             [f"Steps {g['first']}–{g['last']} | {', '.join(g['stages'])} | {g['successful']} successful, {g['failed']} failed" for g in groups])
    s.heading("Notable PPO decisions")
    notable=[r for r in rows if str(r["step"]) in j["notable"]]
    s.table(("Step","PPO-selected action","Target","Outcome","Reward","Security meaning"),
        [(r["step"],r.get("action_kind") or UNKNOWN,r.get("target_entity") or UNKNOWN,outcome(r.get("success")),r["reward"],"; ".join(j["notable"][str(r["step"])])) for r in notable])
    s=doc.section("Trajectory finding and defensive implications")
    s.heading("What the AI found")
    s.prose(final, f"The simulator recorded {outcome(end.get('success')).lower()} as the final action outcome and {end['reward']} as its reward. This is evidence of zero-shot task performance in this validation episode. It establishes neither a vulnerability severity nor a production breach.")
    s.heading("Why progression was possible")
    prereqs=end.get("prerequisites")
    s.prose("The last action lists these simulated prerequisites: "+(", ".join(map(str,prereqs)) if prereqs else UNKNOWN)+". No control intervention was tested.")
    s.heading("What defenders can learn")
    stages={stage for g in groups for stage in g["stages"]}
    themes={"Reconnaissance & Planning":"Review unnecessary service exposure and discovery visibility.",
            "Initial Access":"Review entry restrictions and audit successful access.",
            "Lateral Movement & Privilege Escalation":"Review segment isolation and privilege boundaries.",
            "Objective Execution / Impact":"Review isolation and access auditing for the recorded objective target."}
    s.table(("Recorded stage grouping","Defensive question to investigate"),[(k,v) for k,v in themes.items() if k in stages])
    s.prose("These are candidate controls for a separate comparison. This episode cannot identify which control would interrupt a similar progression.")
    s=doc.section("MITRE ATT&CK context")
    framework(s,[(stage,f"Step {r['step']} · {r.get('target_entity') or UNKNOWN}",r.get("framework_mappings")) for stage,r in zip(j["stages"],rows)])
    s=doc.section("Final outcome and next steps")
    s.table(("Stage","Recorded event","Outcome"),[(label,r.get("simulator_action") or UNKNOWN,outcome(r.get("success"))) for label,r in (("Opening",rows[0]),("Terminal",end))])
    s.prose(final)
    s.heading("What PPO Contributed")
    s.prose("The learned policy supplied autonomous action selection at each successive state. That produced an attributable sequence of decisions on an unseen validation topology, connecting reinforcement learning to the dissertation’s attack-path discovery question.",
            f"For this policy and topology, the recorded objective was {'achieved' if summary['objective_reached'] else 'unreached'}. Compare other registered policy/topology pairs before drawing a distribution-level conclusion.")
    s.figure("Final visual summary", [f"Unseen validation topology {identity['topology_seed']}",f"Frozen policy {identity['training_seed']}",
            f"{total} sequential decisions",f"{len(groups)} chronological groups",f"Objective: {summary['terminal_outcome']}","Defensive interpretation: review observed transitions and test safeguards separately"])
    s=doc.section("Recorded Assessment Progression — Final State")
    add_figures(s, rows, {}, "Designated objective", summary["objective_reached"], ppo=True)
    s=doc.section("Evidence appendix")
    s.table(("Identity","Recorded value"),[(k.replace("_"," "),identity[k]) for k in ("policy_sha256_before","policy_sha256_after","checkpoint_sha256","topology_hash","protocol_sha256")])
    s.prose(f"Trajectory source: {d['provenance']['trajectory_file']}. The companion JSON preserves original rows, evidence availability, mapping sources and file digests.")
    s.heading("Technical step table")
    s.table(("Step / line","Action index","Simulated action","Target","Outcome","Reward"),
            [(f"{r['step']} / {entry['source_line']}",r.get("rl_action_index",UNKNOWN),r.get("simulator_action") or UNKNOWN,r.get("target_entity") or UNKNOWN,outcome(r.get("success")),r["reward"]) for entry,r in zip(d["steps"],rows)])
    return doc


def html_report(data):
    return layout.html(document(data))


def pdf_report(data):
    return layout.pdf(document(data))
