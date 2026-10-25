export type Fact = Record<string, unknown>;
export interface GraphNode {
  id: string;
  type: string;
  label: string;
  metadata: Fact;
  provenance: string[];
  status: string;
}
export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  metadata: Fact;
  evidence_refs: string[];
}
export interface GraphDTO {
  source: "neo4j";
  graph_id: string | null;
  nodes: GraphNode[];
  edges: GraphEdge[];
}
export const pages = [
  "Dashboard",
  "Assets",
  "Network Graph",
  "Vulnerabilities",
  "Attack Paths",
  "Digital Twin",
  "Simulation",
  "Reports",
] as const;
export type Page = (typeof pages)[number];
