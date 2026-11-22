import { SimpleMap } from "./SimpleMap";
import { EpisodePlayback } from "../EpisodePlayback";
import { IconGraph } from "./IconGraph";
import { shortId } from "../../components/EvidenceDisplay";
import { useEffect, useRef, useState } from "react";
import Sigma from "sigma";
import type { GraphDTO } from "../../types";
import { buildGraph } from "../../graph/model";
import { Details } from "../../components/Details";
import { EnterpriseStructure, type AssessmentTopology } from "./EnterpriseStructure";
import { get } from "../../api/client";
export function GraphWorkspace({ data, assessment, token }: { data: GraphDTO; assessment?: AssessmentTopology; token?:string }) {
  const [view,setView]=useState("Simple View");
  const [episode,setEpisode]=useState(0);
  const [mode,setMode]=useState(assessment && data.metadata?.view!=="evidence"?"Combined":"Evidence");
  const [linked,setLinked]=useState<AssessmentTopology|null>(null);
  const [contextError,setContextError]=useState("");
  const report=(data.metadata?.projection as {report_id?:string}|undefined)?.report_id;
  useEffect(()=>{
    setLinked(null);setContextError("");
    if(!token||!report||!data.graph_id||data.source!=="neo4j")return;
    const abort=new AbortController();
    const query=new URLSearchParams({graph_id:data.graph_id,report_id:report});
    get<AssessmentTopology|null>("engineering-simulations/published-topology?"+query,token,abort.signal)
      .then(v=>{if(!abort.signal.aborted)setLinked(v);}).catch(()=>{if(!abort.signal.aborted)setContextError("Configured scenario unavailable. Showing recorded projection only.");});
    return ()=>abort.abort();
  },[token,report,data.graph_id,data.source]);
  const [services,setServices]=useState(true);
  const recordedEdges=data.edges.filter(e=>e.evidence_refs.length>0 && e.metadata.step!=null && e.type!=="SUPPORTED_BY_EVIDENCE");
  const recordedIds=new Set(recordedEdges.flatMap(e=>[e.source,e.target]));
  const visible = mode==="Attack / Provenance" ? {...data,
    nodes:data.nodes.filter(n=>recordedIds.has(n.id)&&(services||!["service","software","finding","vulnerability"].includes(n.type.toLowerCase()))),
    edges:recordedEdges} : data;
  const container = useRef<HTMLDivElement>(null);
  const camera = useRef<Sigma | null>(null);
  const [search, setSearch] = useState(""),
    [nodeType, setNodeType] = useState(""),
    [edgeType, setEdgeType] = useState("");
  const [selected, setSelected] = useState<unknown>(null),
    [error, setError] = useState("");
  useEffect(() => {
    setSelected(null);
    setError("");
    if (!container.current || !data.nodes.length) return;
    let renderer: Sigma | undefined;
    try {
      let activeNode: string | null = null, activeEdge: string | null = null, hoverEdge: string | null = null;
      renderer = new Sigma(
        buildGraph(visible, search, nodeType, edgeType),
        container.current,
        {
          renderEdgeLabels: true,
          stagePadding: data.nodes.length <= 2 ? 90 : 30,
          labelGridCellSize: 100,
          labelDensity: 0.65,
          nodeReducer: (id, attrs) => ({...attrs, label: shortId(attrs.label), highlighted: id===activeNode || attrs.highlighted}),
          edgeReducer: (id, attrs) => ({...attrs, label: id===activeEdge || id===hoverEdge ? attrs.label : "", forceLabel: id===activeEdge || id===hoverEdge}),
          enableEdgeEvents: true,
          labelColor: { color: "#dbe4ec" },
          defaultEdgeType: "arrow",
        },
      );
      camera.current = renderer;
      renderer.on("clickNode", ({node}) => { activeNode=node; activeEdge=null; setSelected(data.nodes.find(n=>n.id===node)); renderer?.refresh(); });
      renderer.on("clickEdge", ({edge}) => { activeEdge=edge; activeNode=null; setSelected(data.edges.find(e=>e.id===edge)); renderer?.refresh(); });
      renderer.on("enterEdge", ({edge}) => { hoverEdge=edge; renderer?.refresh(); });
      renderer.on("leaveEdge", () => { hoverEdge=null; renderer?.refresh(); });
      renderer.on("clickStage", () => {activeNode=null; activeEdge=null; setSelected(null); renderer?.refresh();});
    } catch (e) {
      setError(e instanceof Error ? e.message : "Graph rendering unavailable");
    }
    return () => {
      camera.current = null;
      renderer?.kill();
    };
  }, [data, search, nodeType, edgeType, mode, services]);
  return (
    <div className="graph-workspace">
      <aside className="filters">
        <nav aria-label="Workspace view">{["Simple View","Attack Replay","Expert Graph"].map(v=><button key={v} aria-pressed={view===v} onClick={()=>{setView(v);if(v==="Attack Replay")setMode("Episode Simulation");}}>{v}</button>)}</nav>
        {view==="Expert Graph"&&<><h3>Graph view</h3>
        <label>Graph mode<select value={mode} onChange={e=>setMode(e.target.value)}>{["Topology","Episode Simulation","Attack / Provenance","Combined","Evidence"].map(m=><option key={m}>{m}</option>)}</select></label>
        {mode==="Attack / Provenance"&&<button onClick={()=>setServices(v=>!v)}>{services?"Collapse services":"Expand services"}</button>}
        <p>Logical architecture layout. Position does not establish routing or reachability.</p>
        {(mode==="Evidence"||mode==="Attack / Provenance")&&<><h3>Projection filters</h3>
        <label>
          Search
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Node label"
          />
        </label>
        <label>
          Node type
          <select
            value={nodeType}
            onChange={(e) => setNodeType(e.target.value)}
          >
            <option value="">All types</option>
            {[...new Set(data.nodes.map((n) => n.type))].map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
        </label>
        <label>
          Relationship
          <select
            value={edgeType}
            onChange={(e) => setEdgeType(e.target.value)}
          >
            <option value="">All relationships</option>
            {[...new Set(data.edges.map((e) => e.type))].map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
        </label>

        <p>Node types · {[...new Set(data.nodes.map(n=>n.type))].join(" · ") || "None recorded"}</p><p>Graph: {data.graph_id ?? "Unavailable"}</p>
        <details><summary>Graph metadata and display limits</summary>
          {data.metadata ? <pre>{JSON.stringify(data.metadata, null, 2)}</pre> : <p>Graph metadata unavailable.</p>}
        </details>
        </>}{contextError&&<p>{contextError}</p>}
        <p>{data.source === "neo4j" ? "Neo4j projection" : "Stored engineering simulation graph"} · evidence-backed relationships only.</p>
        <p>Unknown and inferred facts are not confirmed facts.</p>
        {data.source === "engineering-simulation" && <p>Green: initial foothold · Gold: configured objective · Coral: recorded access · Red edges: failed simulator actions.</p>}
        </>}
      </aside>
      {view==="Simple View"?<SimpleMap data={data} assessment={assessment??linked??undefined}/>:mode==="Episode Simulation"?<><label>Recorded episode<select value={episode} onChange={e=>setEpisode(Number(e.target.value))}>{(assessment??linked)?.episodes.map((_,i)=><option key={i} value={i}>Episode {i+1}</option>)}</select></label>
      {(assessment??linked)?.episodes[episode]?<EpisodePlayback key={String(data.graph_id)+episode} model={{identity:{...(assessment??linked)?.identity,graph_id:data.graph_id,metadata:data.metadata,episode_index:episode,lineage:((assessment??linked)?.identity?.runs as unknown[]|undefined)?.[episode]},events:(assessment??linked)!.episodes[episode].events,registered:false}} data={data} assessment={assessment??linked??undefined}/>:<p>Recorded episode unavailable for this graph selection.</p>}</>:<IconGraph data={data} assessment={assessment??linked??undefined} mode={mode}/>}
      {(mode==="Evidence"||mode==="Attack / Provenance")&&<Details value={selected} />}
    </div>
  );
}
