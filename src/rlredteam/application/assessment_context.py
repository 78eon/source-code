"""Evidence vocabulary and compact reference tables shared by human-readable reports."""
from .assessment_layout import Section

UNKNOWN = "Not recorded"


def outcome(value):
    return "Successful" if value is True else "Unsuccessful" if value is False else UNKNOWN


def context(section: Section, recorded, derived, contextual, unknown):
    section.heading("Evidence quality")
    section.table(("Status", "How to read the evidence"), [
        ("Recorded", recorded), ("Derived", derived), ("Contextual", contextual), ("Unknown", unknown)])
    section.heading("Scope and exclusions")
    section.prose("Included: synthetic security modelling, recorded decisions, attack-path analysis and defensive interpretation.",
                  "Excluded: live scanning, credential use on real systems, destructive actions, denial of service, persistence, exploit validation and held-out evaluation.")


def framework(section, actions):
    rows={}
    for stage,action,mappings in actions:
        for m in mappings or []:
            key=(m.get("technique_id"),m.get("tactic_id") or m.get("tactic_name"))
            if key not in rows:
                rows[key]=(stage,m.get("tactic_name") or m.get("tactic_id") or UNKNOWN,
                           m.get("technique_name") or UNKNOWN,m.get("technique_id") or UNKNOWN,action)
    section.prose("ATT&CK provides a vocabulary for comparing recorded behaviour. Each entry gives its first recorded context. A mapping alone establishes neither real compromise nor control failure.")
    if rows:
        section.table(("Stage","Tactic","Technique","ID","Recorded context"),rows.values())
    else:
        section.prose("No technique mapping was retained for these events.")


def comparison(s):
    s.table(("Capability","Registered PPO research","Engineering simulation"),[
        ("Decision engine","MaskablePPO","V2 reasoner / masked heuristic"),
        ("Learned policy / frozen checkpoint","Yes / yes","No / no"),
        ("Registered experiment","Yes","No"),
        ("Wizard topology","Compatibility unvalidated","Supported bounded configuration"),
        ("Evidence","Validation trajectory","Canonical attack and provenance graph"),
        ("Purpose","Research evaluation","Engineering assessment and demonstration")])
