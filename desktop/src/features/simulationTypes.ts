export interface Subnet {label:string; size:number; role:string}
export interface Device {category:string; count:number; os_family:string; os_version:string; role:string; criticality:string; subnet:number; internet_exposed:boolean; crown_jewel:boolean}
export interface Service {name:string; version:string; port:number; device_group:number|null; accessibility:string; authentication_required:boolean; importance:string}
export interface SimulationSpec {
 critical_asset_label?:string|null;
 example_origin?:{preset_id:string;version:number;specification_sha256:string;topology_sha256:string}|null;
 name:string; description:string; organisation_type:string; scenario_label:string; analyst_notes:string; seed:number; hosts:number;
 subnets:Subnet[]; segmentation:string; dmz:boolean; devices:Device[]; services:Service[];
 vulnerabilities:{mode:string; risk_profile:string; cvss_min:number; cvss_max:number; per_host:number; access:string; privilege:string; service_index:number; catalogue_ids:string[]};
 identity_roles:string[]; controls:{firewall_segmentation:boolean; endpoint_protection:boolean; mfa:boolean; restricted_administration:boolean; service_hardening:boolean; patch_coverage:number; monitoring:boolean};
 target_group:number; objective:string; max_steps:number; episodes:number; policy_id:string; action_masking:true; partial_observability:true; reward_profile:string;
}
export interface SimulationStatus {limits?:{services:number}; enabled:boolean; disclaimer:string; default_spec:SimulationSpec; device_categories:string[]; service_categories:string[]; policy:{id:string;label:string}; unsupported:string[]}
export const SIMULATION_DISCLAIMER="SIMULATED SECURITY ASSESSMENT — NOT A LIVE PENETRATION TEST";
export interface ExampleScenario {
 preset_id:string; version:number; label:string; purpose:string; difficulty:string; critical_asset:string;
 hosts:number; subnets:number; risk_profile:string; segmentation:string; default_seed:number;
 specification_sha256:string; topology_sha256:string; specification:SimulationSpec;
 evidence_class:"engineering_simulation"; research_status:"not_registered";
}
export function loadExample(example:ExampleScenario):SimulationSpec {
 return {...structuredClone(example.specification),example_origin:{preset_id:example.preset_id,version:example.version,
  specification_sha256:example.specification_sha256,topology_sha256:example.topology_sha256}};
}
